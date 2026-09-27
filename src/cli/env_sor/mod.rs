//! The CLI side of SoR units (SoRLa storage phase 3, contract C2/C3):
//! validating the manifest block, recording it at apply time, and assembling
//! what `op env reconcile` (k8s) and `op env up` (Cloud Run) need from the
//! env's store.

#[cfg(feature = "creds-gcp")]
pub(crate) mod cloudrun;
mod inputs;
mod prepare;
mod publish;
mod validate;

pub(crate) use inputs::{
    refuse_dev_secrets_path_override, require_dev_store_backend, resolve_sor_inputs,
};
pub(crate) use prepare::{prepare, record_applied};
pub(crate) use publish::StoreRoutePublisher;
pub(crate) use validate::validate_sor_units;

use std::collections::BTreeSet;

use greentic_deploy_spec::EnvId;

use crate::cli::OpError;
use crate::environment::LocalFsStore;
use crate::environment::sor_units::{AppliedSorUnit, SorUnit};

// Reached by the tests below and by `tests_stale` through `super::*`.
#[cfg(test)]
use crate::env_packs::k8s::manifests::SecretsBackend;
#[cfg(test)]
use crate::env_packs::k8s::sor_reconcile::SorRoutePublisher;
#[cfg(test)]
use greentic_deploy_spec::Environment;
#[cfg(test)]
use prepare::{SorLanePlacement, is_owned_by, prepare_with_override};

/// Record the declared SoR units (`<env_dir>/sor-units.json`) under the env
/// flock. Called by the `set-sor-units` apply step.
pub(crate) fn set_sor_units(
    store: &LocalFsStore,
    env_id: &EnvId,
    units: &[SorUnit],
) -> Result<(), OpError> {
    store
        .transact(env_id, |locked| locked.save_sor_units(units))
        .map_err(OpError::from)
}

/// Store URIs stripped from the dev-store seed that ships into routers and
/// workers: every input a declared unit reads, UNIONED with every input the
/// applied ledger records. Those are the SoR's own credentials (its database
/// URL above all), and no flow or worker reads them — the worker needs only
/// the route document. The ledger half is what keeps a retired or re-pointed
/// unit's old inputs out of the seed until reconcile has deleted them.
pub(crate) fn sor_input_uris(
    env_id: &EnvId,
    units: &[SorUnit],
    ledger: &[AppliedSorUnit],
) -> Vec<String> {
    let declared = units.iter().flat_map(SorUnit::input_refs);
    let recorded = ledger
        .iter()
        .flat_map(|a| a.input_refs.iter().map(String::as_str));
    declared
        .chain(recorded)
        .collect::<BTreeSet<&str>>()
        .into_iter()
        .map(|rel| crate::cli::secrets::dev_store_key(env_id, rel))
        .collect()
}

#[cfg(test)]
mod tests_stale;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::secrets::{DEV_STORE_KIND_PATH, put_env_secret};
    use crate::cli::tests_common::{make_binding, make_env};
    use crate::env_packs::k8s::manifests::SecretsBackend;
    use crate::environment::EnvironmentStore as _;
    use crate::environment::sor_units::AppliedSorUnit;
    use greentic_deploy_spec::CapabilitySlot;

    pub(super) fn seeded_with(unit_ids: &[&str]) -> (tempfile::TempDir, LocalFsStore, Environment) {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Secrets,
            "greentic.secrets.dev-store@1.0.0",
        ));
        store.save(&env).unwrap();
        let mut units = Vec::new();
        for id in unit_ids {
            let mut u = crate::env_packs::k8s::manifests::sor::tests::unit();
            u.unit_id = id.to_string();
            u.sor = format!("{id}-sor");
            u.answers_ref = format!("default/_/sor-{id}/answers");
            u.postgres_url_ref = format!("default/_/sor-{id}/postgres_url");
            u.shared_secret_ref = format!("default/_/sor-{id}/shared_secret");
            for (rel, v) in [
                (&u.answers_ref, r#"{"tenant":{"tenant_id":"acme"}}"#),
                (&u.postgres_url_ref, "postgres://x"),
                (&u.shared_secret_ref, "s"),
            ] {
                put_env_secret(
                    &store,
                    &env,
                    &env.environment_id,
                    DEV_STORE_KIND_PATH,
                    rel,
                    v,
                )
                .unwrap();
            }
            units.push(u);
        }
        set_sor_units(&store, &env.environment_id, &units).unwrap();
        (dir, store, env)
    }

    pub(super) fn applied(id: &str, ns: &str) -> AppliedSorUnit {
        AppliedSorUnit {
            unit_id: id.into(),
            sor: format!("{id}-sor"),
            namespace: ns.into(),
            cloud_run: None,
            input_refs: ["answers", "postgres_url", "shared_secret"]
                .iter()
                .map(|n| format!("default/_/sor-{id}/{n}"))
                .collect(),
        }
    }

    pub(super) fn ns(namespace: &'static str) -> impl Fn() -> Result<SorLanePlacement, OpError> {
        move || {
            Ok(SorLanePlacement::K8s {
                namespace: namespace.to_string(),
            })
        }
    }

    fn cloud_run_applied(id: &str) -> AppliedSorUnit {
        AppliedSorUnit {
            namespace: String::new(),
            cloud_run: Some(
                crate::environment::sor_units::CloudRunSorPlacement::for_unit(
                    "proj",
                    "europe-west1",
                    "gtc-local",
                    id,
                ),
            ),
            ..applied(id, "unused")
        }
    }

    #[test]
    fn nothing_declared_and_nothing_recorded_means_no_sor_phase() {
        let (_d, store, env) = seeded_with(&[]);
        assert!(
            prepare_with_override(
                &store,
                &env,
                &ns("gtc-local"),
                &SecretsBackend::DevStore,
                None
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn prepare_records_intent_before_the_cluster_is_touched() {
        let (_d, store, env) = seeded_with(&["b"]);
        store
            .transact(&env.environment_id, |l| {
                l.save_sor_ledger(&[applied("a", "gtc-local")])
            })
            .unwrap();
        let prepared = prepare_with_override(
            &store,
            &env,
            &ns("gtc-local"),
            &SecretsBackend::DevStore,
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            store.load_sor_ledger(&env.environment_id).unwrap(),
            vec![applied("a", "gtc-local"), applied("b", "gtc-local")],
            "a unit this reconcile may create is on record even if the reconcile dies"
        );
        assert_eq!(prepared.retired_units, vec![applied("a", "gtc-local")]);
        assert_eq!(prepared.retired_sors, vec!["a-sor".to_string()]);
        record_applied(&store, &env.environment_id, &prepared).unwrap();
        assert_eq!(
            store.load_sor_ledger(&env.environment_id).unwrap(),
            vec![applied("b", "gtc-local")]
        );
    }

    #[test]
    fn a_unit_whose_namespace_moved_is_retired_in_the_old_namespace_only() {
        let (_d, store, env) = seeded_with(&["b"]);
        store
            .transact(&env.environment_id, |l| {
                l.save_sor_ledger(&[applied("b", "gtc-old")])
            })
            .unwrap();
        let prepared = prepare_with_override(
            &store,
            &env,
            &ns("gtc-new"),
            &SecretsBackend::DevStore,
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(prepared.retired_units, vec![applied("b", "gtc-old")]);
        assert!(
            prepared.retired_sors.is_empty(),
            "the SoR itself is still declared"
        );
    }

    #[test]
    fn prepare_refuses_before_writing_anything_when_an_input_is_missing() {
        let (_d, store, env) = seeded_with(&["b"]);
        crate::cli::secrets::delete_env_secret(
            &store,
            &env.environment_id,
            "default/_/sor-b/shared_secret",
        )
        .unwrap();
        assert!(
            prepare_with_override(
                &store,
                &env,
                &ns("gtc-local"),
                &SecretsBackend::DevStore,
                None
            )
            .is_err()
        );
        assert!(
            store
                .load_sor_ledger(&env.environment_id)
                .unwrap()
                .is_empty()
        );
    }

    /// `get_env_secret` honours `GREENTIC_DEV_SECRETS_PATH` while the shipped
    /// seed does not, so the inputs would come from a different store than the
    /// one that ships: refused before anything is read or recorded.
    #[test]
    fn a_dev_secrets_path_override_is_refused_before_any_input_is_read() {
        let (_d, store, env) = seeded_with(&["b"]);
        // Deleting an input proves the refusal comes before the read: the
        // override error wins over the missing-input error.
        crate::cli::secrets::delete_env_secret(
            &store,
            &env.environment_id,
            "default/_/sor-b/shared_secret",
        )
        .unwrap();
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
        assert!(
            store
                .load_sor_ledger(&env.environment_id)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_vault_backend_is_refused_before_any_input_is_read() {
        let (_d, store, env) = seeded_with(&["b"]);
        crate::cli::secrets::delete_env_secret(
            &store,
            &env.environment_id,
            "default/_/sor-b/shared_secret",
        )
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
        let msg = prepare_with_override(&store, &env, &ns("gtc-local"), &vault, None)
            .err()
            .expect("refused")
            .to_string();
        assert!(msg.contains("dev-store"), "{msg}");
        assert!(
            store
                .load_sor_ledger(&env.environment_id)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_cloud_run_ledger_entry_refuses_a_k8s_run_before_anything_is_written() {
        let (_d, store, env) = seeded_with(&["b"]);
        let recorded = vec![cloud_run_applied("a")];
        store
            .transact(&env.environment_id, |l| l.save_sor_ledger(&recorded))
            .unwrap();
        let msg = prepare_with_override(
            &store,
            &env,
            &ns("gtc-local"),
            &SecretsBackend::DevStore,
            None,
        )
        .err()
        .expect("refused")
        .to_string();
        assert!(msg.contains("greentic.deployer.gcp-cloudrun"), "{msg}");
        assert!(msg.contains("greentic.deployer.k8s"), "{msg}");
        assert!(msg.contains("`a`"), "{msg}");
        assert_eq!(
            store.load_sor_ledger(&env.environment_id).unwrap(),
            recorded,
            "nothing widened"
        );
    }

    #[test]
    fn a_corrupt_ledger_entry_is_refused_naming_the_unit() {
        let (_d, store, env) = seeded_with(&["b"]);
        let mut both = cloud_run_applied("a");
        both.namespace = "gtc-local".into();
        store
            .transact(&env.environment_id, |l| {
                l.save_sor_ledger(std::slice::from_ref(&both))
            })
            .unwrap();
        let msg = prepare_with_override(
            &store,
            &env,
            &ns("gtc-local"),
            &SecretsBackend::DevStore,
            None,
        )
        .err()
        .expect("refused")
        .to_string();
        assert!(msg.contains("`a`"), "{msg}");
    }

    #[test]
    fn placed_units_pair_each_render_with_its_own_entry() {
        let (_d, store, env) = seeded_with(&["a", "b"]);
        let prepared = prepare_with_override(
            &store,
            &env,
            &ns("gtc-local"),
            &SecretsBackend::DevStore,
            None,
        )
        .unwrap()
        .unwrap();
        let pairs: Vec<(String, String)> = prepared
            .placed_units()
            .map(|(render, entry)| (render.unit.unit_id.clone(), entry.unit_id.clone()))
            .collect();
        assert_eq!(
            pairs,
            vec![("a".into(), "a".into()), ("b".into(), "b".into())]
        );
    }
}
