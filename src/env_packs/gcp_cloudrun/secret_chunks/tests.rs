use super::*;
use crate::env_packs::gcp_cloudrun::deploy_target::CloudRunTarget;
use crate::env_packs::{
    deployer::{Deployer, conformance::build_fixture_env},
    gcp_cloudrun::{
        GcpCloudRunDeployerHandler,
        deploy_target::{InMemoryCloudRun, validate_secret_payload},
        deployer::{GcpCloudRunParams, environment_secret_name},
    },
};
use greentic_deploy_spec::{RevisionId, secret_chunks as protocol};
use serde_json::json;
use std::sync::Arc;

const PIN: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn bytes(len: usize) -> Vec<u8> {
    let mut x = 0xabc123efu32;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}
fn fixture() -> (greentic_deploy_spec::Environment, String) {
    let mut env = build_fixture_env();
    env.revisions[0].runtime_image_digest = Some(PIN.into());
    let image = GcpCloudRunParams::for_env(&env).image_ref_for(Some(PIN));
    (env, image)
}
#[tokio::test]
async fn secret_chunks_boundary_reported_size_and_incompressible_multimegabyte_store() {
    for len in [65_536, 65_537, 70_737, 2 * 1024 * 1024 + 13] {
        let (env, image) = fixture();
        let target = Arc::new(InMemoryCloudRun::default());
        if len > 65_536 {
            target.enable_secret_chunks_for(&image);
        }
        let input = bytes(len);
        let handler = GcpCloudRunDeployerHandler::with_target_and_dev_secrets(
            target.clone(),
            Some(input.clone()),
        );
        let r = &env.revisions[0];
        handler
            .warm_revision(&env, r.revision_id, None)
            .await
            .unwrap();
        let mounts = target.service_secrets_for(r.deployment_id).unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].mount_dir, "/seed");
        let boot = target.service_env_for(r.deployment_id).unwrap();
        assert_eq!(
            boot.iter()
                .any(|(key, value)| key == protocol::TRANSPORT_ENV && value == protocol::SCHEMA),
            len > protocol::SECRET_VERSION_CAP
        );
        let versions = target.secret_versions_of(&mounts[0].secret_name);
        assert!(
            versions
                .iter()
                .all(|v| v.payload.len() <= 65_536 && !v.destroyed)
        );
        let read = |version: &str| {
            versions[version.parse::<usize>().unwrap() - 1]
                .payload
                .clone()
        };
        if len == 65_536 {
            assert_eq!(mounts[0].items.len(), 2);
            assert_eq!(read(&mounts[0].items[1].version), input);
            assert_eq!(mounts[0].items[1].rel_path, protocol::STORE_PATH);
        } else {
            assert!(
                mounts[0]
                    .items
                    .iter()
                    .all(|i| i.rel_path != protocol::STORE_PATH)
            );
            let item = mounts[0]
                .items
                .iter()
                .find(|i| i.rel_path == protocol::MANIFEST_PATH)
                .unwrap();
            let manifest = ChunkManifest::decode(&read(&item.version)).unwrap();
            assert_eq!(
                manifest
                    .reconstruct(|c| {
                        assert!(
                            mounts[0]
                                .items
                                .iter()
                                .any(|i| i.rel_path == c.path && i.version == c.version)
                        );
                        Ok(read(&c.version))
                    })
                    .unwrap(),
                input
            );
            assert!(
                item.version.parse::<usize>().unwrap()
                    > manifest
                        .chunks
                        .iter()
                        .map(|c| c.version.parse::<usize>().unwrap())
                        .max()
                        .unwrap()
            );
        }
        let before = target.secrets();
        handler
            .warm_revision(&env, r.revision_id, None)
            .await
            .unwrap();
        assert_eq!(
            target.secrets(),
            before,
            "immutable retry never restages the store"
        );
    }
}
#[tokio::test]
async fn secret_chunks_unsupported_runtime_fails_before_any_seed_write_or_service_change() {
    for pinned in [false, true] {
        let (mut env, _) = fixture();
        if !pinned {
            env.revisions[0].runtime_image_digest = None;
        }
        let target = Arc::new(InMemoryCloudRun::default());
        let handler = GcpCloudRunDeployerHandler::with_target_and_dev_secrets(
            target.clone(),
            Some(bytes(70_737)),
        );
        let err = handler
            .warm_revision(&env, env.revisions[0].revision_id, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("verified"));
        assert!(target.secrets().is_empty());
        assert!(target.services().is_empty());
        assert!(target.seed_artifacts().is_empty());
    }
}
#[tokio::test]
async fn secret_chunks_revision_pin_must_be_the_image_with_the_verified_capability() {
    let (env, _) = fixture();
    let target = Arc::new(InMemoryCloudRun::default());
    let other = format!("sha256:{}", "b".repeat(64));
    target.enable_secret_chunks_for(&GcpCloudRunParams::for_env(&env).image_ref_for(Some(&other)));
    let handler = GcpCloudRunDeployerHandler::with_target_and_dev_secrets(
        target.clone(),
        Some(bytes(70_737)),
    );
    assert!(
        handler
            .warm_revision(
                &env,
                env.revisions[0].revision_id,
                Some(&json!({"runtime_image_digest":other}))
            )
            .await
            .is_err()
    );
    assert!(target.secrets().is_empty());
}
#[tokio::test]
async fn secret_chunks_partial_upload_retry_and_rollback_preserve_previous_versions_and_traffic() {
    let (mut env, image) = fixture();
    let target = Arc::new(InMemoryCloudRun::default());
    target.enable_secret_chunks_for(&image);
    let legacy =
        GcpCloudRunDeployerHandler::with_target_and_dev_secrets(target.clone(), Some(bytes(1024)));
    let old = env.revisions[0].clone();
    // The incident has a single serving revision. The generic conformance
    // fixture starts with a 50/50 split, so make the recorded rollback target
    // agree with the first-create provider allocation before warming it.
    env.traffic_splits
        .iter_mut()
        .find(|s| s.deployment_id == old.deployment_id)
        .unwrap()
        .entries = vec![greentic_deploy_spec::TrafficSplitEntry {
        revision_id: old.revision_id,
        weight_bps: 10_000,
    }];
    legacy
        .warm_revision(&env, old.revision_id, None)
        .await
        .unwrap();
    let traffic = target.traffic_for(old.deployment_id).unwrap();
    let name = environment_secret_name(&GcpCloudRunParams::for_env(&env).secret_prefix);
    let rollback_versions = target.secret_versions_of(&name);
    let mut next = old.clone();
    next.revision_id = RevisionId::new();
    next.sequence += 1;
    env.revisions.push(next.clone());
    let handler = GcpCloudRunDeployerHandler::with_target_and_dev_secrets(
        target.clone(),
        Some(bytes(70_737)),
    );
    target.fail_secret_upload_after(Some(rollback_versions.len() + 2));
    assert!(
        handler
            .warm_revision(&env, next.revision_id, None)
            .await
            .is_err()
    );
    assert_eq!(target.traffic_for(old.deployment_id).unwrap(), traffic);
    assert!(
        target
            .get_revision_status(&super::super::deploy_target::RevisionRef {
                deployment_id: old.deployment_id,
                revision_id: next.revision_id,
                project: "fixture".into(),
                region: "fixture".into()
            })
            .await
            .is_err()
    );
    assert!(
        target
            .secret_versions_of(&name)
            .iter()
            .all(|v| ChunkManifest::decode(&v.payload).is_err()),
        "manifest is never published on partial upload"
    );
    target.fail_secret_upload_after(None);
    handler
        .warm_revision(&env, next.revision_id, None)
        .await
        .unwrap();
    assert_eq!(
        target
            .traffic_for(old.deployment_id)
            .unwrap()
            .into_iter()
            .filter(|t| t.percent > 0)
            .collect::<Vec<_>>(),
        traffic
    );
    let after = target.secret_versions_of(&name);
    assert_eq!(
        &after[..rollback_versions.len()],
        rollback_versions.as_slice()
    );
    legacy
        .warm_revision(&env, old.revision_id, None)
        .await
        .unwrap();
    legacy
        .apply_traffic_split(&env, old.deployment_id, None)
        .await
        .unwrap();
    assert_eq!(target.traffic_for(old.deployment_id).unwrap(), traffic);
    assert!(after.iter().all(|v| !v.destroyed));
}
#[test]
fn secret_chunks_payload_bounds_and_capability_config_are_safe() {
    assert!(validate_secret_payload(&bytes(65_536)).is_ok());
    assert!(validate_secret_payload(&bytes(65_537)).is_err());
    assert!(!config_advertises_chunks(
        r#"{"config":{"Labels":{"io.greentic.secret-store.chunks":"2"}}}"#
    ));
    assert!(config_advertises_chunks(
        r#"{"config":{"Labels":{"io.greentic.secret-store.chunks":"1"}}}"#
    ));
    assert!(!config_advertises_chunks("sensitive-credential-content"));
}

#[test]
fn secret_chunks_capability_is_bound_to_config_and_manifest_or_index_digest() {
    let image = format!("ghcr.io/greenticai/greentic-start@{PIN}");
    let config = r#"{"os":"linux","architecture":"amd64","config":{"Labels":{"io.greentic.secret-store.chunks":"1"}}}"#;
    let config_digest = format!("sha256:{}", protocol::digest(config.as_bytes()));
    assert!(verify_image_capability(&image, PIN, None, &config_digest, config).unwrap());
    assert!(
        verify_image_capability(&image, "sha256:child", Some(PIN), &config_digest, config).unwrap()
    );
    assert!(verify_image_capability(&image, "sha256:other", None, &config_digest, config).is_err());
    assert!(
        verify_image_capability(&image, PIN, Some("sha256:other"), &config_digest, config).is_err()
    );
    assert!(verify_image_capability(&image, PIN, None, "sha256:other", config).is_err());
    let wrong_arch = config.replace("amd64", "arm64");
    let hash = format!("sha256:{}", protocol::digest(wrong_arch.as_bytes()));
    assert!(!verify_image_capability(&image, PIN, None, &hash, &wrong_arch).unwrap());
    let bad = "sensitive-credential-content";
    let hash = format!("sha256:{}", protocol::digest(bad.as_bytes()));
    assert!(
        !verify_image_capability(&image, PIN, None, &hash, bad)
            .unwrap_err()
            .to_string()
            .contains(bad)
    );
}
