//! Per-revision runtime pin on the k8s worker (unified update L2b): a
//! revision's pin replaces the tag/digest of its OWN worker image only; the
//! repository and the router image stay the environment's.

use super::*;
use crate::env_packs::deployer::conformance::build_fixture_env;

const PIN_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PIN_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn params_with(image: &str) -> K8sParams {
    let env = build_fixture_env();
    let mut p = K8sParams::for_env(&env);
    p.runtime_image = image.to_string();
    p
}

fn worker_image(deployment: &Value) -> String {
    deployment["spec"]["template"]["spec"]["containers"][0]["image"]
        .as_str()
        .expect("worker image")
        .to_string()
}

#[test]
fn image_for_none_is_the_answer() {
    let p = params_with("ghcr.io/greenticai/greentic-start-distroless:develop");
    assert_eq!(p.image_for(None), p.runtime_image);
}

#[test]
fn image_for_replaces_tag() {
    let p = params_with("ghcr.io/greenticai/greentic-start-distroless:develop");
    assert_eq!(
        p.image_for(Some(PIN_A)),
        format!("ghcr.io/greenticai/greentic-start-distroless@{PIN_A}")
    );
}

#[test]
fn image_for_replaces_digest() {
    let p = params_with(&format!("ghcr.io/greenticai/rt@{PIN_A}"));
    assert_eq!(
        p.image_for(Some(PIN_B)),
        format!("ghcr.io/greenticai/rt@{PIN_B}")
    );
}

#[test]
fn image_for_keeps_registry_port() {
    let p = params_with("registry.internal:5000/greentic/start:1.2");
    assert_eq!(
        p.image_for(Some(PIN_A)),
        format!("registry.internal:5000/greentic/start@{PIN_A}")
    );
    // A port with no tag at all must not be mistaken for a tag.
    let p = params_with("registry.internal:5000/greentic/start");
    assert_eq!(
        p.image_for(Some(PIN_A)),
        format!("registry.internal:5000/greentic/start@{PIN_A}")
    );
}

#[test]
fn an_invalid_pin_is_ignored_and_cannot_change_the_repository() {
    let p = params_with("registry.internal:5000/greentic/start:1.2");
    for bad in [
        "evil.example/x@sha256:aaaa",
        "sha256:aa/bb",
        "other:tag",
        "sha256:aa@bb",
        "sha256:",
        // Strict definition: 64 lowercase hex only.
        "sha256:aaaa",
        "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
    ] {
        assert_eq!(p.image_for(Some(bad)), p.runtime_image, "{bad}");
    }
}

#[test]
fn worker_renders_pin_router_renders_answer() {
    let mut env = build_fixture_env();
    let answer = "ghcr.io/greenticai/greentic-start-distroless:develop";
    let p = params_with(answer);
    env.revisions[0].runtime_image_digest = Some(PIN_A.into());
    let worker = render_worker_deployment(&env, &env.revisions[0], &p);
    assert_eq!(
        worker_image(&worker),
        format!("ghcr.io/greenticai/greentic-start-distroless@{PIN_A}")
    );
    let router = render_router_deployment(&env, &p);
    assert_eq!(worker_image(&router), answer);
}

#[test]
fn two_revisions_render_two_images_with_one_router_image() {
    let mut env = build_fixture_env();
    let mut second = env.revisions[0].clone();
    second.revision_id = greentic_deploy_spec::RevisionId::new();
    env.revisions[0].runtime_image_digest = Some(PIN_A.into());
    second.runtime_image_digest = Some(PIN_B.into());
    let p = params_with("ghcr.io/greenticai/greentic-start-distroless:develop");
    let a = worker_image(&render_worker_deployment(&env, &env.revisions[0], &p));
    let b = worker_image(&render_worker_deployment(&env, &second, &p));
    assert_ne!(a, b);
    assert!(a.ends_with(PIN_A) && b.ends_with(PIN_B));
    assert_eq!(
        worker_image(&render_router_deployment(&env, &p)),
        p.runtime_image
    );
}

#[test]
fn unpinned_worker_renders_answer_byte_identical() {
    let env = build_fixture_env();
    assert!(env.revisions[0].runtime_image_digest.is_none());
    let p = params_with("ghcr.io/greenticai/greentic-start-distroless:develop");
    let worker = render_worker_deployment(&env, &env.revisions[0], &p);
    assert_eq!(worker_image(&worker), p.runtime_image);
    // The pin changes the image field and nothing else.
    let mut pinned_env = env.clone();
    pinned_env.revisions[0].runtime_image_digest = Some(PIN_A.into());
    let mut pinned = render_worker_deployment(&pinned_env, &pinned_env.revisions[0], &p);
    pinned["spec"]["template"]["spec"]["containers"][0]["image"] = json!(p.runtime_image);
    assert_eq!(pinned, worker);
}
