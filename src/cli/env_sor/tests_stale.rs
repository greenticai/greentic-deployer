//! A retired or re-pointed SoR unit's OLD inputs: kept out of the seed that
//! ships into routers and workers, and deleted from the store by the reconcile.
//! Also the no-SoR and Vault retire-only paths of `prepare`.

use super::tests::{applied, ns, seeded_with};
use super::*;
use crate::cli::secrets::{DEV_STORE_KIND_PATH, dev_store_key, get_env_secret, put_env_secret};

/// Store URIs the staged seed can still resolve, among `rels`.
fn resolvable_in_seed(store: &LocalFsStore, env: &Environment, rels: &[String]) -> Vec<String> {
    use greentic_secrets_lib::{DevStore, SecretsStore};
    let env_id = &env.environment_id;
    let staged = crate::cli::env::read_dev_secrets_bytes(store, env_id)
        .unwrap()
        .expect("a seed");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".dev.secrets.env");
    std::fs::write(&path, &staged).unwrap();
    let dev = DevStore::with_path(path).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rels.iter()
        .filter(|rel| rt.block_on(dev.get(&dev_store_key(env_id, rel))).is_ok())
        .cloned()
        .collect()
}

fn present(store: &LocalFsStore, env: &Environment, rel: &str) -> bool {
    get_env_secret(store, env, &env.environment_id, DEV_STORE_KIND_PATH, rel)
        .unwrap()
        .0
        .is_some()
}

#[test]
fn a_retired_units_inputs_stay_out_of_the_seed_and_are_deleted_from_the_store() {
    let (_d, store, env) = seeded_with(&["a"]);
    let env_id = &env.environment_id;
    let old = applied("a", "gtc-local");
    store
        .transact(env_id, |l| l.save_sor_ledger(std::slice::from_ref(&old)))
        .unwrap();
    // `op env apply` with `sor_units: []`.
    set_sor_units(&store, env_id, &[]).unwrap();
    // A control key the workers DO need, so an empty answer below means
    // "excluded", not "the seed could not be read".
    let worker = "default/_/worker/token".to_string();
    put_env_secret(&store, &env, env_id, DEV_STORE_KIND_PATH, &worker, "w").unwrap();
    assert_eq!(
        resolvable_in_seed(&store, &env, std::slice::from_ref(&worker)),
        vec![worker.clone()]
    );

    assert!(
        resolvable_in_seed(&store, &env, &old.input_refs).is_empty(),
        "the ledger keeps a retired unit's inputs out of the seed"
    );

    let prepared = prepare_with_override(
        &store,
        &env,
        &ns("gtc-local"),
        &SecretsBackend::DevStore,
        None,
    )
    .unwrap()
    .expect("a retire phase");
    assert_eq!(prepared.stale_input_refs, {
        let mut refs = old.input_refs.clone();
        refs.sort();
        refs
    });
    StoreRoutePublisher::new(&store, &env)
        .publish(&[], &prepared.retired_sors, &prepared.stale_input_refs)
        .unwrap();
    for rel in &old.input_refs {
        assert!(!present(&store, &env, rel), "`{rel}` is deleted");
    }
    record_applied(&store, env_id, &prepared).unwrap();
    assert!(store.load_sor_ledger(env_id).unwrap().is_empty());
}

#[test]
fn a_re_pointed_ref_removes_the_old_target_and_excludes_the_new_one() {
    let (_d, store, env) = seeded_with(&["b"]);
    let env_id = &env.environment_id;
    let old_url = "default/_/sor-b/postgres_url_v1".to_string();
    put_env_secret(
        &store,
        &env,
        env_id,
        DEV_STORE_KIND_PATH,
        &old_url,
        "postgres://old",
    )
    .unwrap();
    // Last reconciled while `postgres_url_ref` still named the old key.
    let mut recorded = applied("b", "gtc-local");
    recorded.input_refs[1] = old_url.clone();
    store
        .transact(env_id, |l| {
            l.save_sor_ledger(std::slice::from_ref(&recorded))
        })
        .unwrap();

    let new_refs = applied("b", "gtc-local").input_refs;
    let mut every_ref = new_refs.clone();
    every_ref.push(old_url.clone());
    assert!(
        resolvable_in_seed(&store, &env, &every_ref).is_empty(),
        "neither the old nor the new target ships"
    );

    let prepared = prepare_with_override(
        &store,
        &env,
        &ns("gtc-local"),
        &SecretsBackend::DevStore,
        None,
    )
    .unwrap()
    .expect("a SoR phase");
    assert_eq!(prepared.stale_input_refs, vec![old_url.clone()]);
    assert!(prepared.retired_units.is_empty(), "the unit itself stays");
    let widened = store.load_sor_ledger(env_id).unwrap();
    assert_eq!(widened.len(), 1);
    assert!(
        widened[0].input_refs.contains(&old_url)
            && new_refs.iter().all(|r| widened[0].input_refs.contains(r)),
        "until the reconcile succeeds both targets stay on record"
    );

    StoreRoutePublisher::new(&store, &env)
        .retire(&prepared.retired_sors, &prepared.stale_input_refs)
        .unwrap();
    assert!(!present(&store, &env, &old_url));
    assert!(
        present(&store, &env, &new_refs[1]),
        "the new target is kept"
    );

    record_applied(&store, env_id, &prepared).unwrap();
    assert_eq!(
        store.load_sor_ledger(env_id).unwrap(),
        vec![applied("b", "gtc-local")]
    );
    assert!(resolvable_in_seed(&store, &env, &new_refs).is_empty());
}

/// An env with no SoR units never resolves the namespace, so bad deployer
/// answers fail wherever they failed before SoR units existed.
#[test]
fn no_sor_units_never_parses_the_deployer_answers() {
    let (_d, store, env) = seeded_with(&[]);
    let refuse =
        || -> Result<String, OpError> { Err(OpError::InvalidArgument("must not be asked".into())) };
    assert!(
        prepare_with_override(&store, &env, &refuse, &SecretsBackend::DevStore, None)
            .unwrap()
            .is_none()
    );
    let (_d, store, env) = seeded_with(&["b"]);
    assert!(matches!(
        prepare_with_override(&store, &env, &refuse, &SecretsBackend::DevStore, None),
        Err(OpError::InvalidArgument(_))
    ));
}

/// Retiring every unit on an env that has since moved to Vault must not
/// wedge it: nothing is declared, so nothing needs the dev store.
#[test]
fn a_vault_env_can_retire_the_units_it_no_longer_declares() {
    let (_d, store, env) = seeded_with(&[]);
    let env_id = &env.environment_id;
    let old = applied("a", "gtc-local");
    store
        .transact(env_id, |l| l.save_sor_ledger(std::slice::from_ref(&old)))
        .unwrap();
    let vault = SecretsBackend::Vault(crate::env_packs::k8s::manifests::VaultBackend {
        addr: "http://vault.vault.svc:8200".to_string(),
        k8s_role: "greentic-worker".to_string(),
        kv_mount: "secret".to_string(),
        kv_prefix: "greentic".to_string(),
        auth_mount: "kubernetes".to_string(),
        transit_mount: "transit".to_string(),
        transit_key: "greentic".to_string(),
        namespace: None,
    });
    let prepared = prepare_with_override(&store, &env, &ns("gtc-local"), &vault, None)
        .unwrap()
        .expect("a retire phase");
    assert_eq!(prepared.retired_units, vec![old]);
    // Every key is absent (the store has none of them): still Ok.
    StoreRoutePublisher::new(&store, &env)
        .retire(&prepared.retired_sors, &prepared.stale_input_refs)
        .unwrap();
}

/// A retire-only run deletes from a dev store too. Under
/// `GREENTIC_DEV_SECRETS_PATH` those deletes would hit the override file while
/// the seed ships the env's own store, so the old inputs would ship forever
/// once the ledger narrows: refused, and nothing recorded or deleted.
#[test]
fn a_retire_only_run_still_refuses_a_dev_secrets_path_override() {
    let (_d, store, env) = seeded_with(&["a"]);
    let env_id = &env.environment_id;
    let old = applied("a", "gtc-local");
    store
        .transact(env_id, |l| l.save_sor_ledger(std::slice::from_ref(&old)))
        .unwrap();
    set_sor_units(&store, env_id, &[]).unwrap();
    let msg = prepare_with_override(
        &store,
        &env,
        &ns("gtc-local"),
        &SecretsBackend::DevStore,
        Some("/elsewhere/.dev.secrets.env".into()),
    )
    .err()
    .expect("refused")
    .to_string();
    assert!(msg.contains("GREENTIC_DEV_SECRETS_PATH"), "{msg}");
    assert_eq!(store.load_sor_ledger(env_id).unwrap(), vec![old.clone()]);
    for rel in &old.input_refs {
        assert!(present(&store, &env, rel), "`{rel}` is untouched");
    }
}

/// A ref recorded outside the unit's own `sor-<unit_id>/` segment (a typo'd
/// ref naming an unrelated key) is never deleted — only reported by path.
#[test]
fn a_stale_ref_outside_the_units_own_segment_is_reported_not_deleted() {
    let (_d, store, env) = seeded_with(&["a"]);
    let env_id = &env.environment_id;
    let foreign = "default/_/worker/api_token".to_string();
    put_env_secret(
        &store,
        &env,
        env_id,
        DEV_STORE_KIND_PATH,
        &foreign,
        "keep-me",
    )
    .unwrap();
    let mut old = applied("a", "gtc-local");
    old.input_refs.push(foreign.clone());
    // Another unit's segment is foreign too.
    old.input_refs
        .push("default/_/sor-other/answers".to_string());
    store
        .transact(env_id, |l| l.save_sor_ledger(std::slice::from_ref(&old)))
        .unwrap();
    set_sor_units(&store, env_id, &[]).unwrap();

    let prepared = prepare_with_override(
        &store,
        &env,
        &ns("gtc-local"),
        &SecretsBackend::DevStore,
        None,
    )
    .unwrap()
    .expect("a retire phase");
    assert!(!prepared.stale_input_refs.contains(&foreign));
    assert_eq!(
        prepared.skipped_input_refs,
        vec!["default/_/sor-other/answers".to_string(), foreign.clone()]
    );
    StoreRoutePublisher::new(&store, &env)
        .retire(&prepared.retired_sors, &prepared.stale_input_refs)
        .unwrap();
    assert!(
        present(&store, &env, &foreign),
        "a foreign key is never deleted"
    );
    assert!(!present(&store, &env, "default/_/sor-a/postgres_url"));
}

#[test]
fn only_the_units_own_canonical_segment_is_owned() {
    assert!(is_owned_by("a", "default/_/sor-a/postgres_url"));
    assert!(is_owned_by("a", "acme/_/sor-a/answers"));
    assert!(!is_owned_by("a", "default/_/sor-ab/answers"));
    assert!(!is_owned_by("ab", "default/_/sor-a/answers"));
    assert!(!is_owned_by("a", "default/ops/sor-a/answers"));
    assert!(!is_owned_by("a", "default/_/worker/token"));
    assert!(!is_owned_by("a", "default/_/sor-a"));
    assert!(!is_owned_by("a", "default/_/sor-a/x/y"));
}
