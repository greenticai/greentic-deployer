use serde_json::Value;
use sha2::{Digest, Sha256};

use super::*;
use crate::env_packs::gcp_cloudrun::deploy_target::InMemoryCloudRun;

const AR_SOURCE: &str = "oci://europe-docker.pkg.dev/proj/repo/unit-0:abc123";

fn seed_of(len: usize) -> Vec<u8> {
    vec![b'x'; len]
}

fn hex_of(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[test]
fn seed_mode_parses_inline_and_auto_only() {
    assert_eq!(SeedMode::parse("inline"), Some(SeedMode::Inline));
    assert_eq!(SeedMode::parse(" AUTO "), Some(SeedMode::Auto));
    assert_eq!(SeedMode::parse("pointer"), None);
    assert_eq!(SeedMode::default(), SeedMode::Inline);
}

#[test]
fn the_pointer_has_exactly_the_contract_shape_and_field_order() {
    let original = seed_of(60_000);
    let uri = "europe-docker.pkg.dev/proj/repo/seed/prod@sha256:abcd";
    let bytes = pointer_bytes(uri, &original);
    let expected = format!(
        r#"{{"$greentic_seed_pointer":1,"kind":"oci","uri":"{uri}","sha256":"{}","size":60000}}"#,
        hex_of(&original)
    );
    assert_eq!(String::from_utf8(bytes.clone()).unwrap(), expected);
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v[POINTER_KEY], 1);
}

#[test]
fn the_reference_sits_in_the_bundles_repository() {
    let seed = seed_of(10);
    let r = seed_reference("Prod", Some(AR_SOURCE), &seed).unwrap();
    assert_eq!(
        r,
        format!(
            "europe-docker.pkg.dev/proj/repo/seed/prod:{}",
            &hex_of(&seed)[..12]
        )
    );
    // Not Artifact Registry, absent, or an env id OCI would refuse: no reference.
    assert_eq!(
        seed_reference("prod", Some("oci://ghcr.io/x/y:1"), &seed),
        None
    );
    assert_eq!(seed_reference("prod", None, &seed), None);
    assert_eq!(seed_reference("a/b", Some(AR_SOURCE), &seed), None);
}

#[tokio::test]
async fn inline_mode_never_pushes_whatever_the_size() {
    let target = InMemoryCloudRun::default();
    let seed = seed_of(SECRET_VERSION_CAP + 1000);
    let staged = stage_seed(
        &target,
        SeedMode::Inline,
        "prod",
        Some(AR_SOURCE),
        seed.clone(),
    )
    .await
    .unwrap();
    assert_eq!(staged, StagedSeed::Inline(seed));
    assert!(target.seed_artifacts().is_empty());
}

#[tokio::test]
async fn auto_stays_inline_and_byte_identical_under_the_threshold() {
    let target = InMemoryCloudRun::default();
    let seed = seed_of(SEED_INLINE_THRESHOLD);
    let staged = stage_seed(
        &target,
        SeedMode::Auto,
        "prod",
        Some(AR_SOURCE),
        seed.clone(),
    )
    .await
    .unwrap();
    assert_eq!(staged.bytes(), seed.as_slice());
    assert!(matches!(staged, StagedSeed::Inline(_)));
    assert!(target.seed_artifacts().is_empty());
}

#[tokio::test]
async fn auto_pushes_a_large_seed_and_stages_a_verifiable_pointer() {
    let target = InMemoryCloudRun::default();
    let seed = seed_of(SEED_INLINE_THRESHOLD + 1);
    let staged = stage_seed(
        &target,
        SeedMode::Auto,
        "prod",
        Some(AR_SOURCE),
        seed.clone(),
    )
    .await
    .unwrap();
    let StagedSeed::Pointer { bytes, reference } = staged else {
        panic!("a seed over the threshold becomes a pointer");
    };
    assert!(bytes.len() < 512, "the staged version is tiny");

    let pushed = target.seed_artifacts();
    let (manifest_digest, pushed_bytes) = pushed.get(&reference).expect("artifact pushed");
    assert_eq!(pushed_bytes, &seed, "the artifact is the original seed");

    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v[POINTER_KEY], 1);
    assert_eq!(v["kind"], "oci");
    assert_eq!(v["size"], seed.len());
    // sha256 is over the ORIGINAL bytes, never the manifest digest.
    assert_eq!(v["sha256"], hex_of(&seed));
    assert_ne!(v["sha256"], manifest_digest.trim_start_matches("sha256:"));
    // The uri is the registry path pinned by the manifest digest, tag dropped.
    assert_eq!(
        v["uri"],
        format!("europe-docker.pkg.dev/proj/repo/seed/prod@{manifest_digest}")
    );
}

#[tokio::test]
async fn a_failed_push_falls_back_inline_while_the_seed_still_fits() {
    let target = InMemoryCloudRun::default();
    target.deny_seed_push();
    let seed = seed_of(SEED_INLINE_THRESHOLD + 10);
    let staged = stage_seed(
        &target,
        SeedMode::Auto,
        "prod",
        Some(AR_SOURCE),
        seed.clone(),
    )
    .await
    .unwrap();
    assert_eq!(staged, StagedSeed::Inline(seed));
}

#[tokio::test]
async fn a_failed_push_of_an_oversize_seed_is_an_error_naming_the_cause() {
    let target = InMemoryCloudRun::default();
    target.deny_seed_push();
    let seed = seed_of(SECRET_VERSION_CAP + 1);
    let err = stage_seed(&target, SeedMode::Auto, "prod", Some(AR_SOURCE), seed)
        .await
        .expect_err("cannot fit inline and cannot be pushed");
    assert!(err.to_string().contains("uploadArtifacts"), "{err}");
}

#[tokio::test]
async fn auto_without_an_artifact_registry_source_is_inline_or_a_clear_error() {
    let target = InMemoryCloudRun::default();
    let mid = seed_of(SEED_INLINE_THRESHOLD + 10);
    let staged = stage_seed(&target, SeedMode::Auto, "prod", None, mid.clone())
        .await
        .unwrap();
    assert_eq!(staged, StagedSeed::Inline(mid));

    let big = seed_of(SECRET_VERSION_CAP + 1);
    let err = stage_seed(
        &target,
        SeedMode::Auto,
        "prod",
        Some("oci://ghcr.io/x/y:1"),
        big,
    )
    .await
    .expect_err("no repository to push to");
    assert!(err.to_string().contains("Artifact Registry"), "{err}");
}
