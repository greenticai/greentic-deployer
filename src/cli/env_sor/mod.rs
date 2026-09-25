//! The CLI side of SoR units (SoRLa storage phase 3, contract C2/C3):
//! validating the manifest block, recording it at apply time, and assembling
//! what `op env reconcile` / `op env up` need from the env's store.

mod inputs;
mod publish;
mod validate;

pub(crate) use inputs::{
    refuse_dev_secrets_path_override, require_dev_store_backend, resolve_sor_inputs,
};
pub(crate) use publish::StoreRoutePublisher;
pub(crate) use validate::validate_sor_units;

use std::collections::BTreeSet;
use std::ffi::OsString;

use greentic_deploy_spec::{EnvId, Environment};

use crate::cli::OpError;
use crate::env_packs::k8s::manifests::SecretsBackend;
use crate::env_packs::k8s::sor_reconcile::{SorReconcile, SorRoutePublisher, SorUnitRender};
use crate::environment::LocalFsStore;
use crate::environment::sor_units::{AppliedSorUnit, SorUnit};

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

/// Store URIs of every declared unit's inputs. Stripped from the dev-store
/// seed that ships into routers and workers: those are the SoR's own
/// credentials (its database URL above all), and no flow or worker reads
/// them — the worker needs only the route document.
pub(crate) fn sor_input_uris(env_id: &EnvId, units: &[SorUnit]) -> Vec<String> {
    units
        .iter()
        .flat_map(SorUnit::input_refs)
        .map(|rel| crate::cli::secrets::dev_store_key(env_id, rel))
        .collect()
}

/// Everything reconcile needs for the SoR phase, resolved before any cluster
/// call.
pub(crate) struct PreparedSor {
    pub(crate) units: Vec<SorUnitRender>,
    /// Ledger entries no declared unit lives at any more (same id AND
    /// namespace): their objects are pruned.
    pub(crate) retired_units: Vec<AppliedSorUnit>,
    /// SoR keys no declared unit claims any more: their route documents are
    /// deleted.
    pub(crate) retired_sors: Vec<String>,
    /// What the ledger narrows to once the reconcile succeeds.
    desired: Vec<AppliedSorUnit>,
}

impl PreparedSor {
    pub(crate) fn as_reconcile<'a>(
        &'a self,
        publisher: &'a dyn SorRoutePublisher,
    ) -> SorReconcile<'a> {
        SorReconcile {
            units: &self.units,
            retired_units: &self.retired_units,
            retired_sors: &self.retired_sors,
            publisher,
        }
    }
}

/// Resolve the SoR phase. `None` when nothing is declared and nothing was
/// ever applied, so an env without SoR units reconciles exactly as before.
///
/// Every refusal happens here, before the ledger or the cluster is touched —
/// the backend and `GREENTIC_DEV_SECRETS_PATH` checks come before any input is
/// read, because the input reader honours that override while the shipped
/// seed does not. Then the ledger is WIDENED to every unit this reconcile may
/// create: a reconcile that dies after applying a unit still leaves it on
/// record for the next one to prune.
pub(crate) fn prepare(
    store: &LocalFsStore,
    env: &Environment,
    namespace: &str,
    backend: &SecretsBackend,
) -> Result<Option<PreparedSor>, OpError> {
    prepare_with_override(
        store,
        env,
        namespace,
        backend,
        std::env::var_os(crate::cli::secrets::DEV_SECRETS_PATH_ENV),
    )
}

/// [`prepare`] with the `GREENTIC_DEV_SECRETS_PATH` value passed in, so the
/// refusal is testable without mutating the process environment.
fn prepare_with_override(
    store: &LocalFsStore,
    env: &Environment,
    namespace: &str,
    backend: &SecretsBackend,
    dev_secrets_path_override: Option<OsString>,
) -> Result<Option<PreparedSor>, OpError> {
    let env_id = &env.environment_id;
    let units = store.load_sor_units(env_id)?;
    let ledger = store.load_sor_ledger(env_id)?;
    if units.is_empty() && ledger.is_empty() {
        return Ok(None);
    }
    require_dev_store_backend(backend)?;
    refuse_dev_secrets_path_override(dev_secrets_path_override)?;
    let renders = resolve_sor_inputs(store, env, &units)?;

    let desired: Vec<AppliedSorUnit> = units
        .iter()
        .map(|u| AppliedSorUnit {
            unit_id: u.unit_id.clone(),
            sor: u.sor.clone(),
            namespace: namespace.to_string(),
        })
        .collect();
    // Retired = applied somewhere no declared unit now lives (same id AND
    // namespace); a unit that only changed its `sor` keeps its objects.
    let retired_units: Vec<AppliedSorUnit> = ledger
        .iter()
        .filter(|a| {
            !desired
                .iter()
                .any(|d| d.unit_id == a.unit_id && d.namespace == a.namespace)
        })
        .cloned()
        .collect();
    let retired_sors: Vec<String> = ledger
        .iter()
        .map(|a| a.sor.clone())
        .filter(|sor| !units.iter().any(|u| &u.sor == sor))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let mut intent = ledger;
    for d in &desired {
        if !intent.contains(d) {
            intent.push(d.clone());
        }
    }
    store.transact(env_id, |locked| locked.save_sor_ledger(&intent))?;

    Ok(Some(PreparedSor {
        units: renders,
        retired_units,
        retired_sors,
        desired,
    }))
}

/// Narrow the ledger to what is now declared. Only after a successful
/// reconcile — a failed one keeps the widened ledger for the next to prune.
pub(crate) fn record_applied(
    store: &LocalFsStore,
    env_id: &EnvId,
    prepared: &PreparedSor,
) -> Result<(), OpError> {
    store
        .transact(env_id, |locked| locked.save_sor_ledger(&prepared.desired))
        .map_err(OpError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::secrets::{DEV_STORE_KIND_PATH, put_env_secret};
    use crate::cli::tests_common::{make_binding, make_env};
    use crate::env_packs::k8s::manifests::SecretsBackend;
    use crate::environment::EnvironmentStore as _;
    use crate::environment::sor_units::AppliedSorUnit;
    use greentic_deploy_spec::CapabilitySlot;

    fn seeded_with(unit_ids: &[&str]) -> (tempfile::TempDir, LocalFsStore, Environment) {
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

    fn applied(id: &str, ns: &str) -> AppliedSorUnit {
        AppliedSorUnit {
            unit_id: id.into(),
            sor: format!("{id}-sor"),
            namespace: ns.into(),
        }
    }

    #[test]
    fn nothing_declared_and_nothing_recorded_means_no_sor_phase() {
        let (_d, store, env) = seeded_with(&[]);
        assert!(
            prepare(&store, &env, "gtc-local", &SecretsBackend::DevStore)
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
        let prepared = prepare(&store, &env, "gtc-local", &SecretsBackend::DevStore)
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
        let prepared = prepare(&store, &env, "gtc-new", &SecretsBackend::DevStore)
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
        assert!(prepare(&store, &env, "gtc-local", &SecretsBackend::DevStore).is_err());
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
            "gtc-local",
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
        let msg = prepare(&store, &env, "gtc-local", &vault)
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
}
