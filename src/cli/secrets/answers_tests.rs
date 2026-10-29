//! A failed `op secrets` answers-file parse must never echo the file's
//! contents: serde prints the offending value (`invalid type: string
//! "<value>"`), and a `put` payload carries a credential (designer contract
//! §7).

use super::*;
use crate::cli::tests_common::{make_binding, make_env};
use tempfile::tempdir;

const SECRET: &str = "TOPSECRET-424242";

fn store() -> (tempfile::TempDir, LocalFsStore) {
    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    let mut env = make_env("local");
    env.packs.push(make_binding(
        CapabilitySlot::Secrets,
        "greentic.secrets.dev-store@1.0.0",
    ));
    store.save(&env).unwrap();
    (dir, store)
}

fn answers_file(name: &str, body: &str) -> (tempfile::TempDir, OpFlags) {
    let dir = tempdir().unwrap();
    let path = dir.path().join(name);
    std::fs::write(&path, body).unwrap();
    (
        dir,
        OpFlags {
            schema_only: false,
            answers: Some(path),
        },
    )
}

fn assert_clean(err: &OpError) {
    let rendered = format!(
        "{err} | {err:?} | {}",
        crate::cli::render_error("secrets", "put", err)
    );
    assert!(!rendered.contains("TOPSECRET"), "value echoed: {rendered}");
    assert!(!rendered.contains("424242"), "value echoed: {rendered}");
}

#[test]
fn a_mistyped_put_payload_does_not_echo_the_value() {
    let (_d, store) = store();
    for (name, body) in [
        (
            "a.json",
            format!(
                r#"{{"environment_id":"local","path":"default/_/infra/cache_redis","value":{{"credential":"{SECRET}"}}}}"#
            ),
        ),
        (
            "b.json",
            r#"{"environment_id":"local","path":"default/_/infra/cache_redis","value":424242}"#
                .to_string(),
        ),
        (
            "c.yaml",
            format!(
                "environment_id: local\npath: default/_/infra/cache_redis\nvalue: 424242\nidempotency_key: [{SECRET}]\n"
            ),
        ),
        (
            "d.answers",
            format!(
                r#"{{"environment_id":"local","path":"x","value":"v","idempotency_key":["{SECRET}"]}}"#
            ),
        ),
    ] {
        let (_f, flags) = answers_file(name, &body);
        let err = put(&store, &flags, None).unwrap_err();
        assert!(
            matches!(err, OpError::AnswersParse { .. }),
            "{name}: {err:?}"
        );
        assert_clean(&err);
    }
}

#[test]
fn a_mistyped_get_payload_does_not_echo_the_value() {
    let (_d, store) = store();
    for (name, body) in [
        (
            "a.json",
            format!(r#"{{"environment_id":"local","path":"x/y/z/w","reveal":"{SECRET}"}}"#),
        ),
        (
            "b.yaml",
            format!("environment_id: local\npath: x/y/z/w\nreveal: {SECRET}\n"),
        ),
    ] {
        let (_f, flags) = answers_file(name, &body);
        let err = get(&store, &flags, None).unwrap_err();
        assert!(
            matches!(err, OpError::AnswersParse { .. }),
            "{name}: {err:?}"
        );
        assert_clean(&err);
    }
}

#[test]
fn an_empty_value_error_names_no_value() {
    let (_d, store) = store();
    let (_f, flags) = answers_file(
        "a.json",
        r#"{"environment_id":"local","path":"default/_/infra/cache_redis","value":""}"#,
    );
    let err = put(&store, &flags, None).unwrap_err();
    assert!(matches!(err, OpError::InvalidArgument(_)), "{err:?}");
    assert_clean(&err);
}

#[test]
fn a_non_canonical_infra_name_error_echoes_the_name_not_the_value() {
    let (_d, store) = store();
    let (_f, flags) = answers_file(
        "a.json",
        &format!(
            r#"{{"environment_id":"local","path":"default/_/infra/vector-store-qdrant","value":"{SECRET}"}}"#
        ),
    );
    let err = put(&store, &flags, None).unwrap_err();
    assert!(matches!(err, OpError::InvalidArgument(_)), "{err:?}");
    assert!(err.to_string().contains("vector-store-qdrant"), "{err}");
    assert_clean(&err);
}
