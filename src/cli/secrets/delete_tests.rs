//! `op secrets delete` and `op secrets list --prefix`.

use super::*;
use crate::cli::tests_common::{make_binding, make_env};
use tempfile::tempdir;

const ENV: &str = "local";
const MCP_A: &str = "acme/_/mcp/ff308b9c-951a-40b8-acea-f62cdd19c8f3.unit-alpha";
const MCP_B: &str = "acme/_/mcp/ff308b9c-951a-40b8-acea-f62cdd19c8f3.unit-beta";
const A2A_A: &str = "acme/_/a2a/0b6f2d8e-1c1d-4f5e-9a7b-3c2d1e0f9a8b.unit-alpha";
const PLAIN: &str = "acme/_/messaging-telegram/telegram_bot_token";

fn store_with(kind: &str) -> (tempfile::TempDir, LocalFsStore) {
    let dir = tempdir().unwrap();
    let store = LocalFsStore::new(dir.path());
    let mut env = make_env(ENV);
    env.packs.push(make_binding(CapabilitySlot::Secrets, kind));
    store.save(&env).unwrap();
    (dir, store)
}

fn dev_store() -> (tempfile::TempDir, LocalFsStore) {
    store_with("greentic.secrets.dev-store@1.0.0")
}

fn put_value(store: &LocalFsStore, path: &str, value: &str) {
    put(
        store,
        &OpFlags::default(),
        Some(SecretsPutPayload {
            environment_id: ENV.to_string(),
            path: path.to_string(),
            value: value.to_string(),
            idempotency_key: None,
        }),
    )
    .unwrap();
}

fn get_value(store: &LocalFsStore, path: &str) -> Option<String> {
    let outcome = get(
        store,
        &OpFlags::default(),
        Some(SecretsGetPayload {
            environment_id: ENV.to_string(),
            path: path.to_string(),
            reveal: true,
        }),
    )
    .unwrap();
    outcome.result["value"].as_str().map(str::to_string)
}

fn delete_path(store: &LocalFsStore, path: &str) -> Result<OpOutcome, OpError> {
    delete(
        store,
        &OpFlags::default(),
        Some(SecretsDeletePayload {
            environment_id: ENV.to_string(),
            path: Some(path.to_string()),
            prefix: None,
            idempotency_key: None,
        }),
    )
}

fn delete_prefix(store: &LocalFsStore, prefix: &str) -> Result<OpOutcome, OpError> {
    delete(
        store,
        &OpFlags::default(),
        Some(SecretsDeletePayload {
            environment_id: ENV.to_string(),
            path: None,
            prefix: Some(prefix.to_string()),
            idempotency_key: None,
        }),
    )
}

fn list_prefix(store: &LocalFsStore, prefix: Option<&str>) -> Result<OpOutcome, OpError> {
    list(
        store,
        &OpFlags::default(),
        Some(SecretsListPayload {
            environment_id: ENV.to_string(),
            prefix: prefix.map(str::to_string),
        }),
    )
}

fn stored_paths(outcome: &OpOutcome, field: &str) -> Vec<String> {
    outcome.result[field]
        .as_array()
        .unwrap_or_else(|| panic!("`{field}` is an array: {}", outcome.result))
        .iter()
        .map(|k| k["path"].as_str().unwrap().to_string())
        .collect()
}

fn dev_path(store: &LocalFsStore) -> PathBuf {
    let env_id = EnvId::try_from(ENV).unwrap();
    env_dev_store_path(store, &env_id).unwrap()
}

/// Every version the backend still holds for `store_uri` — tombstones
/// included. Empty means the key is gone from the file, not merely hidden.
fn versions_on_disk(store: &LocalFsStore, store_uri: &str) -> usize {
    let backend = secrets_provider_dev::DevBackend::with_persistence(dev_path(store)).unwrap();
    let uri = greentic_secrets_lib::spec::SecretUri::parse(store_uri).unwrap();
    greentic_secrets_lib::spec::SecretsBackend::versions(&backend, &uri)
        .unwrap()
        .len()
}

#[test]
fn delete_removes_an_existing_key_and_get_no_longer_returns_it() {
    let (_dir, store) = dev_store();
    put_value(&store, MCP_A, "tok-a");
    put_value(&store, MCP_B, "tok-b");

    let outcome = delete_path(&store, MCP_A).unwrap();

    assert_eq!(outcome.noun, "secrets");
    assert_eq!(outcome.op, "delete");
    assert_eq!(outcome.result["deleted"], true);
    assert_eq!(
        outcome.result["store_uri"],
        format!("secrets://default/{MCP_A}")
    );
    assert_eq!(
        outcome.result["secret_ref"],
        format!("secret://{ENV}/{MCP_A}")
    );
    assert_eq!(get_value(&store, MCP_A), None);
    // The sibling unit's credential is untouched.
    assert_eq!(get_value(&store, MCP_B).as_deref(), Some("tok-b"));
}

#[test]
fn delete_drops_the_key_from_the_file_instead_of_tombstoning_it() {
    // The store file ships whole into every workload; a tombstone would keep
    // the old value's ciphertext in it.
    let (_dir, store) = dev_store();
    put_value(&store, A2A_A, "tok");
    let uri = format!("secrets://default/{A2A_A}");
    assert_eq!(versions_on_disk(&store, &uri), 1);

    delete_path(&store, A2A_A).unwrap();

    assert_eq!(versions_on_disk(&store, &uri), 0);
}

#[test]
fn delete_of_a_non_verbatim_key_uses_the_env_segment() {
    let (_dir, store) = dev_store();
    put_value(&store, PLAIN, "bot");
    let outcome = delete_path(&store, PLAIN).unwrap();
    assert_eq!(outcome.result["deleted"], true);
    assert_eq!(
        outcome.result["store_uri"],
        format!("secrets://{ENV}/{PLAIN}")
    );
    assert_eq!(get_value(&store, PLAIN), None);
}

#[test]
fn deleting_a_missing_key_is_idempotent() {
    let (_dir, store) = dev_store();
    // No store file at all yet.
    let first = delete_path(&store, MCP_A).unwrap();
    assert_eq!(first.result["deleted"], false);
    assert!(
        !dev_path(&store).exists(),
        "a delete must not create the store"
    );

    // A store that exists but does not hold the key.
    put_value(&store, MCP_B, "tok-b");
    let second = delete_path(&store, MCP_A).unwrap();
    assert_eq!(second.result["deleted"], false);

    // Deleting the same key twice: true, then false.
    assert_eq!(delete_path(&store, MCP_B).unwrap().result["deleted"], true);
    assert_eq!(delete_path(&store, MCP_B).unwrap().result["deleted"], false);
}

#[test]
fn delete_validates_the_path_like_put() {
    let (_dir, store) = dev_store();
    for bad in [
        "acme/default/mcp/x",                    // literal default team
        "acme/_/mcp",                            // wrong depth
        "acme/_/messaging/Not-Canonical",        // non-canonical name outside mcp/a2a
        "default/_/k8s-deployer/deployer_token", // reserved deployer credential
    ] {
        let err = delete_path(&store, bad).unwrap_err();
        assert!(
            matches!(err, OpError::InvalidArgument(_)),
            "`{bad}` must be refused, got {err:?}"
        );
    }
}

#[test]
fn delete_requires_exactly_one_of_path_or_prefix() {
    let (_dir, store) = dev_store();
    for (path, prefix) in [(None, None), (Some(MCP_A), Some("acme/_/mcp/"))] {
        let err = delete(
            &store,
            &OpFlags::default(),
            Some(SecretsDeletePayload {
                environment_id: ENV.to_string(),
                path: path.map(str::to_string),
                prefix: prefix.map(str::to_string),
                idempotency_key: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "{err:?}");
    }
}

#[test]
fn delete_on_a_non_dev_store_backend_is_not_yet_implemented() {
    let (_dir, store) = store_with("greentic.secrets.aws@1.0.0");
    let err = delete_path(&store, MCP_A).unwrap_err();
    assert!(matches!(err, OpError::NotYetImplemented(_)), "{err:?}");
}

#[test]
fn delete_is_audited() {
    let (dir, store) = dev_store();
    put_value(&store, MCP_A, "tok");
    delete_path(&store, MCP_A).unwrap();
    let log = std::fs::read_to_string(dir.path().join(ENV).join("audit/events.jsonl")).unwrap();
    let event: Value = log
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .find(|e| e["verb"] == "delete")
        .expect("a delete audit event");
    assert_eq!(event["noun"], "secrets");
    assert_eq!(event["target"]["path"], MCP_A);
    assert!(!log.contains("tok\""), "no value may reach the audit log");
}

#[test]
fn list_with_a_prefix_shows_key_names_and_never_values() {
    let (_dir, store) = dev_store();
    put_value(&store, A2A_A, "super-secret-a2a-value");
    put_value(&store, MCP_A, "super-secret-mcp-value");

    let outcome = list_prefix(&store, Some("acme/_/a2a/")).unwrap();

    assert_eq!(outcome.result["prefix"], "acme/_/a2a/");
    assert_eq!(
        stored_paths(&outcome, "stored_keys"),
        vec![A2A_A.to_string()]
    );
    assert_eq!(
        outcome.result["stored_keys"][0]["store_uri"],
        format!("secrets://default/{A2A_A}")
    );
    let rendered = outcome.result.to_string();
    assert!(
        !rendered.contains("super-secret"),
        "a value leaked: {rendered}"
    );
}

#[test]
fn list_prefix_filters_by_exact_category_and_by_name_prefix() {
    let (_dir, store) = dev_store();
    put_value(&store, MCP_A, "a");
    put_value(&store, MCP_B, "b");
    put_value(&store, "acme/_/mcp/other-server", "c");
    put_value(&store, A2A_A, "d");
    // Same category under another team: a different scope.
    put_value(&store, "acme/sales/mcp/other-server", "e");

    let all_mcp = list_prefix(&store, Some("acme/_/mcp")).unwrap();
    assert_eq!(
        stored_paths(&all_mcp, "stored_keys"),
        vec![
            MCP_A.to_string(),
            MCP_B.to_string(),
            "acme/_/mcp/other-server".to_string()
        ]
    );

    let one_unit = list_prefix(
        &store,
        Some("acme/_/mcp/ff308b9c-951a-40b8-acea-f62cdd19c8f3.unit-b"),
    )
    .unwrap();
    assert_eq!(
        stored_paths(&one_unit, "stored_keys"),
        vec![MCP_B.to_string()]
    );

    // `mc` is not the `mcp` category: the category never matches by prefix.
    let partial_category = list_prefix(&store, Some("acme/_/mc/")).unwrap();
    assert!(stored_paths(&partial_category, "stored_keys").is_empty());

    let plain = list_prefix(&store, Some("acme/_/messaging-telegram/")).unwrap();
    assert!(stored_paths(&plain, "stored_keys").is_empty());
}

#[test]
fn list_prefix_on_an_empty_store_is_empty_and_creates_nothing() {
    let (_dir, store) = dev_store();
    let outcome = list_prefix(&store, Some("acme/_/mcp/")).unwrap();
    assert!(stored_paths(&outcome, "stored_keys").is_empty());
    assert!(!dev_path(&store).exists());
}

#[test]
fn list_without_a_prefix_keeps_its_old_shape() {
    let (_dir, store) = dev_store();
    put_value(&store, MCP_A, "a");
    let outcome = list_prefix(&store, None).unwrap();
    let keys: Vec<&str> = outcome
        .result
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        vec![
            "environment_id",
            "known_refs",
            "namespace",
            "note",
            "secrets_kind",
            "snapshot_at"
        ]
    );
}

#[test]
fn list_prefix_on_a_non_dev_store_backend_is_not_yet_implemented() {
    let (_dir, store) = store_with("greentic.secrets.aws@1.0.0");
    let err = list_prefix(&store, Some("acme/_/mcp/")).unwrap_err();
    assert!(matches!(err, OpError::NotYetImplemented(_)), "{err:?}");
}

#[test]
fn delete_prefix_purges_every_key_under_it_and_nothing_else() {
    let (_dir, store) = dev_store();
    put_value(&store, MCP_A, "a");
    put_value(&store, MCP_B, "b");
    put_value(&store, A2A_A, "c");
    put_value(&store, PLAIN, "d");

    let outcome = delete_prefix(&store, "acme/_/mcp/").unwrap();

    assert_eq!(outcome.result["deleted"], true);
    assert_eq!(outcome.result["deleted_count"], 2);
    assert_eq!(
        stored_paths(&outcome, "deleted_keys"),
        vec![MCP_A.to_string(), MCP_B.to_string()]
    );
    assert_eq!(get_value(&store, MCP_A), None);
    assert_eq!(get_value(&store, MCP_B), None);
    assert_eq!(get_value(&store, A2A_A).as_deref(), Some("c"));
    assert_eq!(get_value(&store, PLAIN).as_deref(), Some("d"));
    let listed = list_prefix(&store, Some("acme/_/mcp/")).unwrap();
    assert!(stored_paths(&listed, "stored_keys").is_empty());

    // Purging an already-empty prefix is a success that removes nothing.
    let again = delete_prefix(&store, "acme/_/mcp/").unwrap();
    assert_eq!(again.result["deleted"], false);
    assert_eq!(again.result["deleted_count"], 0);
}

#[test]
fn delete_prefix_refuses_to_touch_the_deployer_credential() {
    let (_dir, store) = dev_store();
    let path = dev_path(&store);
    let uri = format!("secrets://{ENV}/default/_/k8s-deployer/deployer_token");
    dev_store_put_credential(&path, &uri, "sa-token").unwrap();

    let err = delete_prefix(&store, "default/_/k8s-deployer/").unwrap_err();

    assert!(matches!(err, OpError::InvalidArgument(_)), "{err:?}");
    assert_eq!(versions_on_disk(&store, &uri), 1, "nothing may be deleted");
}

#[test]
fn prefix_parsing_accepts_three_or_four_segments_only() {
    for (raw, rendered) in [
        ("acme/_/mcp", "acme/_/mcp/"),
        ("acme/_/mcp/", "acme/_/mcp/"),
        ("/acme/_/mcp/", "acme/_/mcp/"),
        ("acme/sales/a2a/x.unit-", "acme/sales/a2a/x.unit-"),
    ] {
        assert_eq!(DevStorePrefix::parse(raw).unwrap().render(), rendered);
    }
    for bad in [
        "acme/_",
        "acme/_/mcp/x/y",
        "/_/mcp/",
        "acme//mcp/",
        "acme/_//",
        "acme/default/mcp/",
    ] {
        assert!(
            matches!(DevStorePrefix::parse(bad), Err(OpError::InvalidArgument(_))),
            "`{bad}` must be refused"
        );
    }
}
