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

#[cfg(feature = "creds-gcp")]
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

#[cfg(feature = "creds-gcp")]
fn split_with_pins(pins: [Option<&str>; 2]) -> Value {
    let mut m = two_revision_manifest([("a", fixture(), 9_000), ("b", provider_fixture(), 1_000)]);
    for (i, pin) in pins.iter().enumerate() {
        if let Some(p) = pin {
            m["bundles"][0]["revisions"][i]["runtime_image_digest"] = json!(p);
        }
    }
    m
}

#[cfg(feature = "creds-gcp")]
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
    let store = LocalFsStore::new(dir.path());
    let parse = |v: Value| -> EnvManifest { serde_json::from_value(v).expect("manifest") };
    let mut manifest = parse(with_cloudrun_answer(single_bundle(None), Some(RUNTIME_A)));
    let _tmp = materialize_inline_pack_answers(&mut manifest).expect("materialize");
    assert_eq!(
        binding_runtime_answer(&store, &manifest, dir.path(), None).expect("answer"),
        Some(RUNTIME_A.to_string())
    );

    let mut unset = parse(with_cloudrun_answer(single_bundle(None), None));
    let _tmp = materialize_inline_pack_answers(&mut unset).expect("materialize");
    assert_eq!(
        binding_runtime_answer(&store, &unset, dir.path(), None).expect("answer"),
        None
    );

    // No deployer pack and no existing binding: nothing to read.
    let bare = parse(single_bundle(None));
    assert_eq!(
        binding_runtime_answer(&store, &bare, dir.path(), None).expect("answer"),
        None
    );
}

#[test]
fn a_non_string_runtime_answer_is_invalid_argument() {
    let dir = tempdir().expect("tempdir");
    let store = LocalFsStore::new(dir.path());
    let mut manifest: EnvManifest =
        serde_json::from_value(with_cloudrun_answer(single_bundle(None), None)).expect("manifest");
    manifest.packs[0].answers = Some(json!({"project": "p", "runtime_image_digest": 5}));
    let _tmp = materialize_inline_pack_answers(&mut manifest).expect("materialize");
    let err = binding_runtime_answer(&store, &manifest, dir.path(), None).unwrap_err();
    assert!(
        matches!(&err, OpError::InvalidArgument(m) if m.contains("runtime_image_digest")),
        "{err:?}"
    );
}

/// The manifest carries NO deployer pack: the Cloud Run binding a previous
/// apply staged (answer A) stays in force, and its answer is read through the
/// binding-answers reader.
#[cfg(feature = "creds-gcp")]
#[test]
fn a_staged_binding_answer_is_used_when_the_manifest_has_no_deployer_pack() {
    let (dir, store) = seeded_store();
    apply_value(
        &store,
        dir.path(),
        "m1.json",
        &with_cloudrun_answer(single_bundle(None), Some(RUNTIME_A)),
    );
    let count = load_local(&store).revisions.len();

    // Unpinned, no packs[]: converged under the staged answer.
    let bare = write_manifest(dir.path(), &single_bundle(None));
    assert_eq!(run_dry(&store, &bare).expect("dry").result["changed"], 0);
    run_apply(&store, &bare).expect("re-apply");
    assert_eq!(load_local(&store).revisions.len(), count);

    // Pinned to the staged answer: still converged.
    apply_value(
        &store,
        dir.path(),
        "m2.json",
        &single_bundle(Some(RUNTIME_A)),
    );
    assert_eq!(load_local(&store).revisions.len(), count);

    // Pinned to B: exactly one new revision, stamped B.
    apply_value(
        &store,
        dir.path(),
        "m3.json",
        &single_bundle(Some(RUNTIME_B)),
    );
    let env = load_local(&store);
    assert_eq!(env.revisions.len(), count + 1);
    assert!(
        env.revisions
            .iter()
            .any(|r| r.runtime_image_digest.as_deref() == Some(RUNTIME_B))
    );
}

// --- the runtime_pin capability gate ---------------------------------------------

fn assert_refused_for_runtime_pin(err: OpError, adapter: &str) {
    let msg = err.to_string();
    assert!(matches!(err, OpError::InvalidArgument(_)), "{msg}");
    assert!(msg.contains("runtime_pin"), "{msg}");
    assert!(msg.contains(adapter), "{msg}");
}

#[test]
fn a_pin_is_refused_on_the_local_deployer() {
    let (dir, store) = seeded_store();
    let path = write_manifest(dir.path(), &single_bundle(Some(RUNTIME_A)));
    let err = run_dry(&store, &path).expect_err("local deployer cannot pin");
    assert_refused_for_runtime_pin(err, "local-process");
    assert!(load_local(&store).revisions.is_empty(), "nothing staged");
}

#[test]
fn a_revision_pin_is_accepted_on_k8s() {
    // Unified update L2b: the k8s deployer declares `runtime_pin`, so the
    // capability gate no longer refuses a manifest pin.
    let (dir, store) = seeded_store();
    let mut manifest =
        two_revision_manifest([("a", fixture(), 9_000), ("b", provider_fixture(), 1_000)]);
    manifest["bundles"][0]["revisions"][1]["runtime_image_digest"] = json!(RUNTIME_B);
    manifest["packs"] = json!([{
        "slot": "deployer", "kind": "greentic.deployer.k8s@1.0.0", "pack_ref": "builtin"
    }]);
    let path = write_manifest(dir.path(), &manifest);
    run_dry(&store, &path).expect("k8s can pin");
}

#[test]
fn a_pin_is_still_refused_on_an_adapter_without_the_capability() {
    // The refusal survives for adapters that do not declare `runtime_pin`
    // (an OLD deployer never gets a pin it would ignore).
    let (dir, store) = seeded_store();
    let mut manifest = single_bundle(Some(RUNTIME_A));
    manifest["packs"] = json!([{
        "slot": "deployer", "kind": crate::defaults::LOCAL_DEPLOYER_PACK, "pack_ref": "builtin"
    }]);
    let path = write_manifest(dir.path(), &manifest);
    let err = run_dry(&store, &path).expect_err("local cannot pin");
    assert_refused_for_runtime_pin(err, "local-process");
}

#[test]
fn an_unpinned_manifest_is_not_gated_on_the_capability() {
    let (dir, store) = seeded_store();
    let path = write_manifest(dir.path(), &single_bundle(None));
    run_dry(&store, &path).expect("no pin, no capability needed");
}

// --- hand-written stage / deploy payloads ------------------------------------------

#[test]
fn hand_written_stage_and_deploy_payloads_refuse_a_malformed_pin() {
    let dir = tempdir().expect("tempdir");
    let store = LocalFsStore::new(dir.path());
    let stage = crate::cli::revisions::RevisionStagePayload {
        environment_id: "local".into(),
        deployment_id: "01JABC000000000000000000ZZ".into(),
        revision_id: None,
        idempotency_key: None,
        bundle_path: None,
        bundle_digest: crate::cli::revisions::default_bundle_digest(),
        bundle_source_uri: None,
        pack_list: Vec::new(),
        pack_list_lock_ref: PathBuf::new(),
        config_digest: crate::cli::revisions::default_config_digest(),
        signature_sidecar_ref: crate::cli::revisions::default_signature_sidecar_ref(),
        drain_seconds: 30,
        runtime_image_digest: Some("develop".into()),
    };
    let err = crate::cli::revisions::stage(&store, &OpFlags::default(), Some(stage))
        .expect_err("malformed pin");
    assert!(
        matches!(&err, OpError::InvalidArgument(m) if m.contains("runtime_image_digest")),
        "{err:?}"
    );

    let deploy = BundleDeployPayload {
        environment_id: "local".into(),
        bundle_id: "b".into(),
        customer_id: None,
        bundle_path: Some(fixture()),
        bundle_source_uri: None,
        remote_pins: None,
        idempotency_key: None,
        config_overrides: None,
        route_binding: None,
        revenue_share: None,
        runtime_image_digest: Some("sha256:ABC".into()),
    };
    let err = crate::cli::deploy::deploy(&store, &OpFlags::default(), Some(deploy))
        .expect_err("malformed pin");
    assert!(
        matches!(&err, OpError::InvalidArgument(m) if m.contains("runtime_image_digest")),
        "{err:?}"
    );
}

#[test]
fn a_pin_only_change_is_described_as_a_runtime_change() {
    let (env, dep) = env_with_one_ready_revision(DIGEST, None, Some(RUNTIME_A));
    assert_eq!(
        live_runtime_change(&env, dep, DIGEST, Some(RUNTIME_B), None),
        Some((RUNTIME_A, RUNTIME_B))
    );
    // Same effective runtime, or a different digest: not a runtime change.
    assert_eq!(
        live_runtime_change(&env, dep, DIGEST, None, Some(RUNTIME_A)),
        None
    );
    let other = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    assert_eq!(
        live_runtime_change(&env, dep, other, Some(RUNTIME_B), None),
        None
    );
}

#[cfg(feature = "creds-gcp")]
#[test]
fn the_plan_names_a_pin_only_change_as_a_runtime_change() {
    let (dir, store) = seeded_store();
    apply_value(
        &store,
        dir.path(),
        "m1.json",
        &with_cloudrun_answer(single_bundle(None), Some(RUNTIME_A)),
    );
    let path = write_manifest(
        dir.path(),
        &with_cloudrun_answer(single_bundle(Some(RUNTIME_B)), Some(RUNTIME_A)),
    );
    let plan = run_dry(&store, &path).expect("dry");
    let detail = plan.result["steps"]
        .as_array()
        .expect("steps")
        .iter()
        .find(|s| s["kind"] == "deploy-bundle")
        .and_then(|s| s["detail"].as_str())
        .expect("deploy-bundle step")
        .to_string();
    assert!(detail.starts_with("runtime "), "{detail}");
    assert!(detail.contains(&RUNTIME_B[..15]), "{detail}");
}

// --- k8s: the answer is the digest part of `runtime_image` --------------------------

const K8S: &str = "greentic.deployer.k8s@1.0.0";

fn k8s_manifest_with_image(image: Option<&str>) -> (EnvManifest, Option<tempfile::TempDir>) {
    let mut answers = json!({});
    if let Some(i) = image {
        answers["runtime_image"] = json!(i);
    }
    let mut manifest: EnvManifest = serde_json::from_value({
        let mut m = single_bundle(None);
        m["packs"] = json!([{
            "slot": "deployer", "kind": K8S, "pack_ref": "builtin", "answers": answers
        }]);
        m
    })
    .expect("manifest");
    let tmp = materialize_inline_pack_answers(&mut manifest).expect("materialize");
    (manifest, tmp)
}

#[test]
fn the_k8s_answer_is_the_digest_of_a_digest_pinned_runtime_image() {
    let dir = tempdir().expect("tempdir");
    let store = LocalFsStore::new(dir.path());
    let (pinned, _pinned_tmp) =
        k8s_manifest_with_image(Some(&format!("ghcr.io/acme/rt@{RUNTIME_A}")));
    assert_eq!(
        binding_runtime_answer(&store, &pinned, dir.path(), None).expect("answer"),
        Some(RUNTIME_A.to_string())
    );
    // A tag ref names no runtime identity: unknown, never equal to a pin.
    let (tag, _tag_tmp) = k8s_manifest_with_image(Some("ghcr.io/acme/rt:develop"));
    assert_eq!(
        binding_runtime_answer(&store, &tag, dir.path(), None).expect("answer"),
        None
    );
    // `repo:tag@sha256:..` still yields the digest.
    let (both, _both_tmp) =
        k8s_manifest_with_image(Some(&format!("ghcr.io/acme/rt:1.2@{RUNTIME_B}")));
    assert_eq!(
        binding_runtime_answer(&store, &both, dir.path(), None).expect("answer"),
        Some(RUNTIME_B.to_string())
    );
    let (unset, _unset_tmp) = k8s_manifest_with_image(None);
    assert_eq!(
        binding_runtime_answer(&store, &unset, dir.path(), None).expect("answer"),
        None
    );
}

#[test]
fn a_non_string_k8s_runtime_image_is_invalid_argument() {
    let dir = tempdir().expect("tempdir");
    let store = LocalFsStore::new(dir.path());
    let mut manifest: EnvManifest = serde_json::from_value({
        let mut m = single_bundle(None);
        m["packs"] = json!([{
            "slot": "deployer", "kind": K8S, "pack_ref": "builtin", "answers": {}
        }]);
        m
    })
    .expect("manifest");
    manifest.packs[0].answers = Some(json!({"runtime_image": 5}));
    let _tmp = materialize_inline_pack_answers(&mut manifest).expect("materialize");
    let err = binding_runtime_answer(&store, &manifest, dir.path(), None).unwrap_err();
    assert!(
        matches!(&err, OpError::InvalidArgument(m) if m.contains("runtime_image")),
        "{err:?}"
    );
}

#[test]
fn tag_answer_is_not_equal_to_any_pin() {
    // Tag-ref environment (answer unknown): an unpinned entry is "unknown",
    // and a pinned entry never converges with an unpinned revision.
    assert_eq!(runtime_pin::effective_runtime(None, None), None);
    assert_ne!(
        runtime_pin::effective_runtime(None, None),
        runtime_pin::effective_runtime(Some(RUNTIME_A), None)
    );
    let (env, dep) = env_with_one_ready_revision(DIGEST, None, None);
    assert!(!deployment_converged(
        &env,
        dep,
        DIGEST,
        None,
        Some(RUNTIME_A),
        None
    ));
}

#[test]
fn legacy_none_revision_with_tag_answer_reconciles_unchanged() {
    // Review Focus: a legacy k8s revision (`None` stamp) under a tag-ref
    // answer, with no pin in the manifest, is converged — no restage.
    let (env, dep) = env_with_one_ready_revision(DIGEST, None, None);
    assert!(deployment_converged(&env, dep, DIGEST, None, None, None));
}

#[test]
fn pinned_revision_is_not_restaged_when_answer_unchanged() {
    let (env, dep) = env_with_one_ready_revision(DIGEST, None, Some(RUNTIME_A));
    // Same pin, tag answer: converged.
    assert!(deployment_converged(
        &env,
        dep,
        DIGEST,
        None,
        Some(RUNTIME_A),
        None
    ));
    // Pin equal to a digest-pinned answer, unpinned entry: converged too.
    assert!(deployment_converged(
        &env,
        dep,
        DIGEST,
        None,
        None,
        Some(RUNTIME_A)
    ));
}

#[test]
fn split_between_pinned_and_unpinned_revision_is_accepted() {
    let (env, dep) = env_with_split(
        &[(DIGEST, None, 10_000), (DIGEST, Some(RUNTIME_B), 0)],
        None,
    );
    let wanted = [
        resolved(DIGEST, 10_000, None),
        resolved(DIGEST, 0, Some(RUNTIME_B)),
    ];
    // Tag-ref answer (None): baseline unknown, candidate pinned.
    assert!(split_converged(&env, dep, &wanted, None));
}
