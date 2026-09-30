//! Unified update L2 (DP3): reuse and convergence compare each revision's
//! EFFECTIVE runtime (`revision pin.or(answer)` vs `entry pin.or(answer)`).
//!
//! Review Focus 4 lives here: a store written before L2 (revisions carry no
//! `runtime_image_digest`) must keep converging — no re-stage, no new
//! revision — on the next identical deploy.

use super::*;
use greentic_deploy_spec::TrafficSplitEntry;

const DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const RUNTIME_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RUNTIME_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CLOUDRUN: &str = "greentic.deployer.gcp-cloudrun@1.0.0";

/// One deployment serving a single `Ready` revision at 100 %.
fn env_with_one_ready_revision(
    digest: &str,
    source_uri: Option<&str>,
    runtime: Option<&str>,
) -> (Environment, DeploymentId) {
    env_with_split(&[(digest, runtime, 10_000)], source_uri)
}

/// One deployment whose split is `entries` (`(digest, runtime pin, bps)`),
/// each a distinct `Ready` revision with drain 0 and `source_uri`.
fn env_with_split(
    entries: &[(&str, Option<&str>, u32)],
    source_uri: Option<&str>,
) -> (Environment, DeploymentId) {
    let mut env = make_env("local");
    let dep = make_bundle_deployment("local", "b");
    let dep_id = dep.deployment_id;
    let mut split = None::<greentic_deploy_spec::TrafficSplit>;
    for (i, (digest, runtime, bps)) in entries.iter().enumerate() {
        let mut rev = make_revision(
            "local",
            "b",
            &dep_id,
            i as u64 + 1,
            RevisionLifecycle::Ready,
        );
        rev.bundle_digest = (*digest).to_string();
        rev.bundle_source_uri = source_uri.map(str::to_string);
        rev.runtime_image_digest = runtime.map(str::to_string);
        rev.drain_seconds = 0;
        match &mut split {
            None => {
                let mut s = make_traffic_split("local", "b", &dep_id, &rev.revision_id, "seed");
                s.entries[0].weight_bps = *bps;
                split = Some(s);
            }
            Some(s) => s.entries.push(TrafficSplitEntry {
                revision_id: rev.revision_id,
                weight_bps: *bps,
            }),
        }
        env.revisions.push(rev);
    }
    env.bundles.push(dep);
    env.traffic_splits.extend(split);
    (env, dep_id)
}

// --- deployment_converged ---------------------------------------------------

#[test]
fn a_legacy_unstamped_revision_still_converges_under_the_same_answer() {
    // Store written before L2: revision has runtime_image_digest None; the
    // binding answer is A; the manifest pins nothing. Must be converged.
    let (env, dep) = env_with_one_ready_revision(DIGEST, Some("oci://r/b:1"), None);
    assert!(deployment_converged(
        &env,
        dep,
        DIGEST,
        Some("oci://r/b:1"),
        None,
        Some(RUNTIME_A)
    ));
}

#[test]
fn a_manifest_pin_equal_to_the_answer_converges_with_a_legacy_revision() {
    let (env, dep) = env_with_one_ready_revision(DIGEST, Some("oci://r/b:1"), None);
    assert!(deployment_converged(
        &env,
        dep,
        DIGEST,
        Some("oci://r/b:1"),
        Some(RUNTIME_A),
        Some(RUNTIME_A)
    ));
}

#[test]
fn a_different_pin_is_not_converged() {
    let (env, dep) = env_with_one_ready_revision(DIGEST, Some("oci://r/b:1"), Some(RUNTIME_A));
    assert!(!deployment_converged(
        &env,
        dep,
        DIGEST,
        Some("oci://r/b:1"),
        Some(RUNTIME_B),
        Some(RUNTIME_A)
    ));
}

#[test]
fn with_no_answer_a_pin_on_a_legacy_revision_is_not_converged() {
    // k8s (no answer): the revision runs whatever the binding runs; a pin
    // arriving is a real change.
    let (env, dep) = env_with_one_ready_revision(DIGEST, None, None);
    assert!(deployment_converged(&env, dep, DIGEST, None, None, None));
    assert!(!deployment_converged(
        &env,
        dep,
        DIGEST,
        None,
        Some(RUNTIME_A),
        None
    ));
}

// --- split_converged --------------------------------------------------------

fn resolved(digest: &str, bps: u32, runtime: Option<&str>) -> ResolvedRevision {
    ResolvedRevision {
        spec: ManifestRevision {
            name: format!("r{bps}"),
            bundle_path: None,
            weight_percent: None,
            weight_bps: Some(bps),
            drain_seconds: None,
            abort_metrics: Vec::new(),
            bundle_source_uri: None,
            bundle_digest: Some(digest.to_string()),
            runtime_image_digest: runtime.map(str::to_string),
        },
        resolved_path: None,
        digest: digest.to_string(),
        runtime_image_digest: runtime.map(str::to_string),
        weight_bps: bps,
    }
}

#[test]
fn split_converged_compares_the_effective_runtime() {
    let (env, dep) = env_with_split(
        &[(DIGEST, None, 10_000), (DIGEST, Some(RUNTIME_B), 0)],
        None,
    );
    // Legacy baseline under answer A + candidate pinned to B: converged.
    let same = [
        resolved(DIGEST, 10_000, None),
        resolved(DIGEST, 0, Some(RUNTIME_B)),
    ];
    assert!(split_converged(&env, dep, &same, Some(RUNTIME_A)));
    // Pinning the baseline to the answer changes nothing it runs.
    let pinned_to_answer = [
        resolved(DIGEST, 10_000, Some(RUNTIME_A)),
        resolved(DIGEST, 0, Some(RUNTIME_B)),
    ];
    assert!(split_converged(
        &env,
        dep,
        &pinned_to_answer,
        Some(RUNTIME_A)
    ));
    // Swapping which entry carries the traffic is a real change.
    let swapped = [
        resolved(DIGEST, 0, None),
        resolved(DIGEST, 10_000, Some(RUNTIME_B)),
    ];
    assert!(!split_converged(&env, dep, &swapped, Some(RUNTIME_A)));
}

// --- split reuse ------------------------------------------------------------

#[test]
fn split_reuse_matches_on_effective_runtime() {
    // Current split [rev1(digest D, runtime None)@100]; wanted
    // [baseline D runtime A @100, candidate D runtime B @0], answer A:
    // rev1 is reused for baseline, candidate must be staged fresh.
    let (env, dep) = env_with_split(&[(DIGEST, None, 10_000)], Some("oci://r/b:1"));
    let wanted = [
        split_reuse::WantedRevision {
            digest: DIGEST,
            source_uri: Some("oci://r/b:1"),
            drain_seconds: 0,
            runtime: Some(RUNTIME_A),
        },
        split_reuse::WantedRevision {
            digest: DIGEST,
            source_uri: Some("oci://r/b:1"),
            drain_seconds: 0,
            runtime: Some(RUNTIME_B),
        },
    ];
    let got =
        split_reuse::reusable_revisions_with_answer(&env, dep, &wanted, None, Some(RUNTIME_A));
    assert!(got[0].is_some());
    assert!(got[1].is_none());
}

#[test]
fn a_legacy_split_member_is_reused_under_the_same_answer() {
    // Review Focus 4, reuse side: None-stamped member, answer A, manifest
    // pins nothing → wanted runtime is the answer, and the member is reused.
    let (env, dep) = env_with_split(&[(DIGEST, None, 10_000)], None);
    let wanted = [split_reuse::WantedRevision {
        digest: DIGEST,
        source_uri: None,
        drain_seconds: 0,
        runtime: runtime_pin::effective_runtime(None, Some(RUNTIME_A)),
    }];
    let got =
        split_reuse::reusable_revisions_with_answer(&env, dep, &wanted, None, Some(RUNTIME_A));
    assert!(got[0].is_some());
}

// --- end to end through apply ---------------------------------------------------

/// `manifest` plus a Cloud Run deployer binding whose answers carry `answer`.
fn with_cloudrun_answer(mut manifest: Value, answer: Option<&str>) -> Value {
    let mut answers = json!({"project": "p", "region": "europe-west1"});
    if let Some(a) = answer {
        answers["runtime_image_digest"] = json!(a);
    }
    manifest["packs"] = json!([{
        "slot": "deployer", "kind": CLOUDRUN, "pack_ref": "builtin", "answers": answers
    }]);
    manifest
}

fn single_bundle(pin: Option<&str>) -> Value {
    let mut m = json!({
        "schema": ENV_MANIFEST_SCHEMA_V1,
        "environment": {"id": "local"},
        "bundles": [{"bundle_id": "quickstart", "bundle_path": fixture()}]
    });
    if let Some(p) = pin {
        m["bundles"][0]["runtime_image_digest"] = json!(p);
    }
    m
}

#[test]
fn an_unstamped_store_converges_on_the_next_identical_deploy() {
    let (dir, store) = seeded_store();
    apply_value(
        &store,
        dir.path(),
        "m1.json",
        &with_cloudrun_answer(single_bundle(None), Some(RUNTIME_A)),
    );
    let before = load_local(&store);
    assert!(
        before
            .revisions
            .iter()
            .all(|r| r.runtime_image_digest.is_none())
    );

    // Identical deploy: nothing to do.
    let same = write_manifest(
        dir.path(),
        &with_cloudrun_answer(single_bundle(None), Some(RUNTIME_A)),
    );
    assert_eq!(run_dry(&store, &same).expect("dry").result["changed"], 0);
    run_apply(&store, &same).expect("re-apply");
    assert_eq!(load_local(&store).revisions.len(), before.revisions.len());

    // Pinning the unit to the runtime it already runs: still nothing to do.
    let pinned_a = with_cloudrun_answer(single_bundle(Some(RUNTIME_A)), Some(RUNTIME_A));
    apply_value(&store, dir.path(), "m2.json", &pinned_a);
    assert_eq!(load_local(&store).revisions.len(), before.revisions.len());

    // A different pin is a new revision stamped with it.
    let pinned_b = with_cloudrun_answer(single_bundle(Some(RUNTIME_B)), Some(RUNTIME_A));
    apply_value(&store, dir.path(), "m3.json", &pinned_b);
    let after = load_local(&store);
    assert_eq!(after.revisions.len(), before.revisions.len() + 1);
    assert!(
        after
            .revisions
            .iter()
            .any(|r| r.runtime_image_digest.as_deref() == Some(RUNTIME_B))
    );
    let converged = write_manifest(dir.path(), &pinned_b);
    assert_eq!(
        run_dry(&store, &converged).expect("dry").result["changed"],
        0
    );
}

fn split_with_pins(pins: [Option<&str>; 2]) -> Value {
    let mut m = two_revision_manifest([("a", fixture(), 9_000), ("b", provider_fixture(), 1_000)]);
    for (i, pin) in pins.iter().enumerate() {
        if let Some(p) = pin {
            m["bundles"][0]["revisions"][i]["runtime_image_digest"] = json!(p);
        }
    }
    m
}

#[test]
fn an_unstamped_split_is_reused_and_only_a_repinned_member_is_restaged() {
    let (dir, store) = seeded_store();
    apply_value(
        &store,
        dir.path(),
        "m1.json",
        &with_cloudrun_answer(split_with_pins([None, None]), Some(RUNTIME_A)),
    );
    let (live, _) = live_split_by_digest(&store);
    let count = load_local(&store).revisions.len();

    // Pinning both members to the answer: converged, nothing staged.
    let to_answer = write_manifest(
        dir.path(),
        &with_cloudrun_answer(
            split_with_pins([Some(RUNTIME_A), Some(RUNTIME_A)]),
            Some(RUNTIME_A),
        ),
    );
    assert_eq!(
        run_dry(&store, &to_answer).expect("dry").result["changed"],
        0
    );
    run_apply(&store, &to_answer).expect("apply");
    assert_eq!(load_local(&store).revisions.len(), count);
    assert_eq!(live_split_by_digest(&store).0, live);

    // Re-pinning `b` stages `b` alone; `a` keeps its revision id.
    apply_value(
        &store,
        dir.path(),
        "m3.json",
        &with_cloudrun_answer(split_with_pins([None, Some(RUNTIME_B)]), Some(RUNTIME_A)),
    );
    let env = load_local(&store);
    assert_eq!(env.revisions.len(), count + 1);
    let a_digest = crate::cli::bundle_stage::sha256_file(&fixture()).expect("digest");
    let (after, _) = live_split_by_digest(&store);
    let a_before = live.iter().find(|e| e.0 == a_digest).expect("a").1;
    let a_after = after.iter().find(|e| e.0 == a_digest).expect("a").1;
    assert_eq!(a_before, a_after, "the unchanged member is reused");
    let b_after = after.iter().find(|e| e.0 != a_digest).expect("b").1;
    let b_rev = env
        .revisions
        .iter()
        .find(|r| r.revision_id == b_after)
        .expect("b revision");
    assert_eq!(b_rev.runtime_image_digest.as_deref(), Some(RUNTIME_B));
}

#[test]
fn execute_deploy_split_stages_a_pinned_revision_instead_of_reusing_an_unpinned_one() {
    // DP2-review carry-forward (b): the Some-pin path through the executor.
    let (dir, store) = seeded_store();
    apply_value(
        &store,
        dir.path(),
        "m1.json",
        &split_of(vec![remote_rev("a", &fixture(), 10_000)]),
    );
    let op = StepOp::DeploySplit {
        env_id: "local".into(),
        bundle_id: "canary".into(),
        customer_id: None,
        config_overrides: None,
        route_binding: None,
        revenue_share: None,
        revisions: vec![SplitRevisionEntry {
            name: "a".into(),
            resolved_path: None,
            expected_digest: crate::cli::bundle_stage::sha256_file(&fixture()).expect("digest"),
            weight_bps: 10_000,
            drain_seconds: None,
            bundle_source_uri: Some("oci://test/a:1".into()),
            runtime_image_digest: Some(RUNTIME_B.into()),
        }],
        reuse_ready: true,
        runtime_answer: None,
    };
    execute_deploy_split(&store, &OpFlags::default(), &op).expect("execute");
    let revisions = load_local(&store).revisions;
    assert_eq!(revisions.len(), 2, "a pin change is a fresh stage");
    assert!(
        revisions
            .iter()
            .any(|r| r.runtime_image_digest.as_deref() == Some(RUNTIME_B))
    );
}

// --- the answer the comparison uses ----------------------------------------------

#[test]
fn the_answer_comes_from_the_cloudrun_deployer_pack_of_the_manifest() {
    let dir = tempdir().expect("tempdir");
    let parse = |v: Value| -> EnvManifest { serde_json::from_value(v).expect("manifest") };
    let mut manifest = parse(with_cloudrun_answer(single_bundle(None), Some(RUNTIME_A)));
    let _tmp = materialize_inline_pack_answers(&mut manifest).expect("materialize");
    assert_eq!(
        binding_runtime_answer(&manifest, dir.path(), None, dir.path()).expect("answer"),
        Some(RUNTIME_A.to_string())
    );

    let mut unset = parse(with_cloudrun_answer(single_bundle(None), None));
    let _tmp = materialize_inline_pack_answers(&mut unset).expect("materialize");
    assert_eq!(
        binding_runtime_answer(&unset, dir.path(), None, dir.path()).expect("answer"),
        None
    );

    // No deployer pack and no existing binding: nothing to read.
    let bare = parse(single_bundle(None));
    assert_eq!(
        binding_runtime_answer(&bare, dir.path(), None, dir.path()).expect("answer"),
        None
    );
}
