//! Tests for [`super`] (the Redis URL secret's reuse and prune rule).
use super::*;
use crate::env_packs::gcp_cloudrun::deploy_target::InMemoryCloudRun;

fn listed(versions: &[(u64, bool)]) -> Vec<SecretVersionInfo> {
    versions
        .iter()
        .map(|(v, enabled)| SecretVersionInfo {
            version: v.to_string(),
            enabled: *enabled,
        })
        .collect()
}

#[test]
fn keeps_current_the_previous_and_anything_newer() {
    let all = listed(&[(1, true), (2, true), (3, true), (4, true), (5, true)]);
    assert_eq!(versions_to_destroy(&all, "4"), vec!["1", "2"]);
    // Nothing older than the previous: nothing to destroy.
    assert!(versions_to_destroy(&listed(&[(1, true), (2, true)]), "2").is_empty());
    assert!(versions_to_destroy(&listed(&[(1, true)]), "1").is_empty());
}

#[test]
fn the_previous_is_the_newest_enabled_one_and_disabled_ones_are_left_alone() {
    // 3 is disabled (someone else's decision): 2 is the immediately previous
    // enabled version, so only 1 goes; 3 is not touched.
    let all = listed(&[(1, true), (2, true), (3, false), (4, true)]);
    assert_eq!(versions_to_destroy(&all, "4"), vec!["1"]);
}

#[test]
fn an_unparseable_current_destroys_nothing() {
    let all = listed(&[(1, true), (2, true), (3, true)]);
    assert!(versions_to_destroy(&all, "latest").is_empty());
}

#[tokio::test]
async fn stage_reuses_a_matching_enabled_version_and_mints_otherwise() {
    let t = InMemoryCloudRun::default();
    let a = stage(&t, "s-redis-url", "local", b"redis://a", "sa@x")
        .await
        .unwrap();
    assert_eq!((a.version.as_str(), a.minted), ("1", true));
    let again = stage(&t, "s-redis-url", "local", b"redis://a", "sa@x")
        .await
        .unwrap();
    assert_eq!((again.version.as_str(), again.minted), ("1", false));
    let b = stage(&t, "s-redis-url", "local", b"redis://b", "sa@x")
        .await
        .unwrap();
    assert_eq!((b.version.as_str(), b.minted), ("2", true));
    // A (still enabled) is reused on a revert, never re-minted.
    let revert = stage(&t, "s-redis-url", "local", b"redis://a", "sa@x")
        .await
        .unwrap();
    assert_eq!((revert.version.as_str(), revert.minted), ("1", false));
}

#[tokio::test]
async fn prune_reports_what_it_destroyed_and_what_it_could_not() {
    let t = InMemoryCloudRun::default();
    for url in ["redis://a", "redis://b", "redis://c", "redis://d"] {
        stage(&t, "s-redis-url", "local", url.as_bytes(), "sa@x")
            .await
            .unwrap();
    }
    let report = prune_after_ready(&t, "s-redis-url", "4").await;
    assert_eq!(report.destroyed, vec!["1", "2"]);
    assert!(report.failed.is_empty());
    // Idempotent: a second prune finds nothing more to do.
    assert_eq!(
        prune_after_ready(&t, "s-redis-url", "4").await,
        PruneReport::default()
    );

    let t = InMemoryCloudRun::default();
    for url in ["redis://a", "redis://b", "redis://c"] {
        stage(&t, "s-redis-url", "local", url.as_bytes(), "sa@x")
            .await
            .unwrap();
    }
    t.deny_version_destroy();
    let report = prune_after_ready(&t, "s-redis-url", "3").await;
    assert!(report.destroyed.is_empty());
    assert_eq!(report.failed, vec!["1"]);
}
