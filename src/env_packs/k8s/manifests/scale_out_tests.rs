//! `replicas` / `redis_url` answers on the k8s worker (issue #661).

use super::*;
use crate::env_packs::deployer::conformance::build_fixture_env;
use crate::env_packs::k8s::manifests::{
    K8sParams, render_environment_manifests, render_worker_deployment,
};
use serde_json::json;

const REDIS: &str = "redis://:s3cret@10.0.0.5:6379/0";

fn obj(v: Value) -> serde_json::Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}

fn params(answers: Value) -> Result<K8sParams, String> {
    K8sParams::from_answers(&build_fixture_env(), Some(&answers))
}

fn worker(p: &K8sParams) -> Value {
    let env = build_fixture_env();
    render_worker_deployment(&env, &env.revisions[0], p)
}

fn env_names(deployment: &Value) -> Vec<String> {
    deployment["spec"]["template"]["spec"]["containers"][0]["env"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|e| e["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn default_is_one_replica_with_no_shared_state_artifacts() {
    let env = build_fixture_env();
    for p in [
        K8sParams::for_env(&env),
        params(json!({})).expect("empty answers"),
    ] {
        let w = worker(&p);
        assert_eq!(w["spec"]["replicas"], 1);
        assert!(!env_names(&w).iter().any(|n| n.contains("REDIS")));
        let manifests = render_environment_manifests(&env, &p);
        assert!(
            !manifests
                .iter()
                .any(|m| m["metadata"]["name"] == SHARED_STATE_SECRET_NAME)
        );
    }
}

#[test]
fn replicas_one_is_accepted_without_a_backend() {
    assert_eq!(parse(&obj(json!({"replicas": "1"}))).unwrap().replicas, 1);
    assert_eq!(parse(&obj(json!({"replicas": 1}))).unwrap().replicas, 1);
}

#[test]
fn blank_and_null_answers_mean_default() {
    let s = parse(&obj(json!({"replicas": "", "redis_url": null}))).unwrap();
    assert_eq!(s, ScaleOut::default());
}

#[test]
fn replicas_above_one_is_refused_without_redis_naming_the_reason() {
    let err = params(json!({"replicas": "3"})).unwrap_err();
    assert!(err.contains("redis_url"), "{err}");
    assert!(err.contains("greentic-start#735"), "{err}");
}

#[test]
fn replicas_above_one_is_accepted_with_redis_and_rendered() {
    let p = params(json!({"replicas": 3, "redis_url": REDIS})).unwrap();
    let w = worker(&p);
    assert_eq!(w["spec"]["replicas"], 3);
    let names = env_names(&w);
    for n in [
        "GREENTIC_RUNNER_SESSION_BACKEND",
        "GREENTIC_RUNNER_STATE_BACKEND",
        "GREENTIC_RUNNER_REDIS_URL",
        "GREENTIC_REVISION_PIN_REDIS_URL",
    ] {
        assert!(names.contains(&n.to_string()), "missing {n}");
    }
    // The URL (with its AUTH) never appears in the pod spec.
    assert!(!w.to_string().contains("s3cret"));
}

#[test]
fn the_url_travels_in_an_env_level_secret_and_workers_get_egress() {
    let env = build_fixture_env();
    let p = params(json!({"replicas": 2, "redis_url": REDIS})).unwrap();
    let manifests = render_environment_manifests(&env, &p);
    let secret = manifests
        .iter()
        .find(|m| m["metadata"]["name"] == SHARED_STATE_SECRET_NAME)
        .expect("shared-state secret");
    assert_eq!(secret["stringData"]["redis-url"], REDIS);
    let policy = manifests
        .iter()
        .find(|m| m["metadata"]["name"] == "gtc-allow-worker-egress")
        .expect("worker egress policy");
    assert_eq!(policy["spec"]["egress"], json!([{}]));
}

#[test]
fn redis_without_extra_replicas_is_allowed() {
    let p = params(json!({"redis_url": REDIS})).unwrap();
    assert_eq!(worker(&p)["spec"]["replicas"], 1);
}

#[test]
fn bounds_and_garbage_are_refused() {
    assert!(parse(&obj(json!({"replicas": "0"}))).is_err());
    assert!(parse(&obj(json!({"replicas": "-1"}))).is_err());
    assert!(parse(&obj(json!({"replicas": "many"}))).is_err());
    assert!(parse(&obj(json!({"replicas": true}))).is_err());
    let over = MAX_WORKER_REPLICAS + 1;
    assert!(parse(&obj(json!({"replicas": over, "redis_url": REDIS}))).is_err());
    assert!(
        parse(&obj(
            json!({"replicas": MAX_WORKER_REPLICAS, "redis_url": REDIS})
        ))
        .is_ok()
    );
}

#[test]
fn bad_redis_urls_are_refused_without_echoing_the_input() {
    for bad in ["rediss://h:6379", "http://h", "not a url", "redis://"] {
        let err = parse(&obj(json!({"redis_url": bad}))).unwrap_err();
        assert!(err.contains("redis_url"), "{err}");
        assert!(!err.contains("not a url"), "input echoed: {err}");
    }
}

#[test]
fn debug_redacts_the_url() {
    let s = parse(&obj(json!({"redis_url": REDIS}))).unwrap();
    assert!(!format!("{s:?}").contains("s3cret"));
}
