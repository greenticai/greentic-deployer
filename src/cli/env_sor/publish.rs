//! The store side of the SoR reconcile's step 4: writing each route document
//! (contract C1) through the same dev-store writer `op secrets put` uses, and
//! deleting what retired or re-pointed units leave behind.

use greentic_deploy_spec::Environment;

use crate::cli::OpError;
use crate::cli::secrets::{DEV_STORE_KIND_PATH, delete_env_secret, get_env_secret, put_env_secret};
use crate::env_packs::k8s::sor_reconcile::{RouteDocument, SorRoutePublisher};
use crate::environment::LocalFsStore;

/// The tenant segment remote lanes use, and the `_` team.
const ROUTE_TENANT: &str = "default";

/// `default/_/sorla/<sor>` — the BARE name; one SoR has one address per env.
pub(crate) fn route_rel_path(sor: &str) -> String {
    format!("{ROUTE_TENANT}/_/sorla/{sor}")
}

/// Writes route documents into the env's own dev store and hands back the
/// seed that ships to the workers.
pub(crate) struct StoreRoutePublisher<'a> {
    store: &'a LocalFsStore,
    env: &'a Environment,
}

impl<'a> StoreRoutePublisher<'a> {
    pub(crate) fn new(store: &'a LocalFsStore, env: &'a Environment) -> Self {
        Self { store, env }
    }

    fn publish_inner(
        &self,
        routes: &[RouteDocument],
        retired_sors: &[String],
        stale_input_refs: &[String],
    ) -> Result<Option<String>, OpError> {
        let env_id = &self.env.environment_id;
        for route in routes {
            let rel = route_rel_path(&route.sor);
            // The dev store re-encrypts on every put: rewriting an unchanged
            // document would change the shipped seed and roll every pod.
            let (current, _, _) =
                get_env_secret(self.store, self.env, env_id, DEV_STORE_KIND_PATH, &rel)?;
            if current.as_deref() != Some(route.value.expose()) {
                put_env_secret(
                    self.store,
                    self.env,
                    env_id,
                    DEV_STORE_KIND_PATH,
                    &rel,
                    route.value.expose(),
                )?;
            }
        }
        self.retire_inner(retired_sors, stale_input_refs)?;
        // Whenever the store file exists this is `Some`, whether or not
        // anything above changed: `None` would ship an EMPTY seed.
        crate::cli::env::read_dev_secrets_b64(self.store, env_id)
    }

    /// Delete retired route documents and stale SoR inputs. An absent key
    /// (or an absent store file) is `Ok`; nothing is ever written.
    fn retire_inner(
        &self,
        retired_sors: &[String],
        stale_input_refs: &[String],
    ) -> Result<(), OpError> {
        let env_id = &self.env.environment_id;
        for sor in retired_sors {
            delete_env_secret(self.store, env_id, &route_rel_path(sor))?;
        }
        for rel in stale_input_refs {
            delete_env_secret(self.store, env_id, rel)?;
        }
        Ok(())
    }
}

impl SorRoutePublisher for StoreRoutePublisher<'_> {
    fn publish(
        &self,
        routes: &[RouteDocument],
        retired_sors: &[String],
        stale_input_refs: &[String],
    ) -> Result<Option<String>, String> {
        // The store verbs' errors name paths and URIs, never a value.
        self.publish_inner(routes, retired_sors, stale_input_refs)
            .map_err(|e| e.to_string())
    }

    fn retire(&self, retired_sors: &[String], stale_input_refs: &[String]) -> Result<(), String> {
        self.retire_inner(retired_sors, stale_input_refs)
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::secrets::{DEV_STORE_KIND_PATH, get_env_secret};
    use crate::cli::tests_common::{make_binding, make_env};
    use crate::env_packs::k8s::sor_reconcile::RouteDocument;
    use crate::environment::EnvironmentStore as _;
    use crate::runtime_secrets::SecretValue;
    use greentic_deploy_spec::CapabilitySlot;

    fn seeded() -> (tempfile::TempDir, LocalFsStore, Environment) {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Secrets,
            "greentic.secrets.dev-store@1.0.0",
        ));
        store.save(&env).unwrap();
        (dir, store, env)
    }

    fn doc(sor: &str, token: &str) -> RouteDocument {
        RouteDocument {
            sor: sor.into(),
            value: SecretValue::from(format!(
                r#"{{"tenant":"acme","token":"{token}","url":"http://x:8787"}}"#
            )),
        }
    }

    fn stored(store: &LocalFsStore, env: &Environment, sor: &str) -> Option<String> {
        get_env_secret(
            store,
            env,
            &env.environment_id,
            DEV_STORE_KIND_PATH,
            &route_rel_path(sor),
        )
        .unwrap()
        .0
    }

    fn store_bytes(store: &LocalFsStore, env: &Environment) -> Vec<u8> {
        let env_dir = store.env_dir(&env.environment_id).unwrap();
        std::fs::read(crate::cli::secrets::resolve_dev_store_path(&env_dir, None)).unwrap()
    }

    #[test]
    fn route_documents_are_written_at_the_bare_sorla_name_and_the_seed_returned() {
        let (_d, store, env) = seeded();
        let publisher = StoreRoutePublisher::new(&store, &env);
        let seed = publisher
            .publish(&[doc("landlord-tenant-sor", "t1")], &[], &[])
            .unwrap();
        assert!(seed.is_some(), "the refreshed seed is what the workers get");
        assert_eq!(
            stored(&store, &env, "landlord-tenant-sor").unwrap(),
            r#"{"tenant":"acme","token":"t1","url":"http://x:8787"}"#
        );
        assert_eq!(
            crate::cli::secrets::dev_store_key(
                &env.environment_id,
                &route_rel_path("landlord-tenant-sor")
            ),
            "secrets://default/default/_/sorla/landlord-tenant-sor"
        );
    }

    #[test]
    fn an_unchanged_route_document_is_not_rewritten() {
        let (_d, store, env) = seeded();
        let publisher = StoreRoutePublisher::new(&store, &env);
        publisher
            .publish(&[doc("landlord-tenant-sor", "t1")], &[], &[])
            .unwrap();
        let before = store_bytes(&store, &env);
        publisher
            .publish(&[doc("landlord-tenant-sor", "t1")], &[], &[])
            .unwrap();
        assert_eq!(
            before,
            store_bytes(&store, &env),
            "a rewrite re-encrypts, changes the seed hash and rolls every worker"
        );
        publisher
            .publish(&[doc("landlord-tenant-sor", "t2")], &[], &[])
            .unwrap();
        assert_ne!(before, store_bytes(&store, &env));
    }

    #[test]
    fn a_retired_route_document_is_deleted_and_an_absent_one_is_fine() {
        let (_d, store, env) = seeded();
        let publisher = StoreRoutePublisher::new(&store, &env);
        publisher
            .publish(&[doc("landlord-tenant-sor", "t1")], &[], &[])
            .unwrap();
        publisher
            .publish(
                &[],
                &["landlord-tenant-sor".into(), "never-written".into()],
                &[],
            )
            .unwrap();
        assert!(stored(&store, &env, "landlord-tenant-sor").is_none());
    }

    /// `None` renders an EMPTY dev-store Secret, so it must mean only "there
    /// is no store file" — never "nothing changed".
    #[test]
    fn the_seed_is_returned_whenever_the_store_file_exists_even_if_nothing_changed() {
        let (_d, store, env) = seeded();
        let publisher = StoreRoutePublisher::new(&store, &env);
        assert!(
            publisher.publish(&[], &[], &[]).unwrap().is_none(),
            "no store file yet"
        );
        publisher
            .publish(&[doc("landlord-tenant-sor", "t1")], &[], &[])
            .unwrap();
        let unchanged = publisher
            .publish(&[doc("landlord-tenant-sor", "t1")], &[], &[])
            .unwrap();
        let expected = crate::cli::env::read_dev_secrets_b64(&store, &env.environment_id)
            .unwrap()
            .expect("a store file exists");
        assert_eq!(unchanged.as_deref(), Some(expected.as_str()));
        assert!(
            publisher.publish(&[], &[], &[]).unwrap().is_some(),
            "nothing to publish still returns the existing seed"
        );
    }

    #[test]
    fn a_publish_error_never_carries_a_route_value() {
        let (_d, store, env) = seeded();
        let publisher = StoreRoutePublisher::new(&store, &env);
        // An unwritable sor key is refused by path validation; the error names
        // the path, never the document.
        let err = publisher
            .publish(&[doc("Bad/Sor", "TOKEN-SECRET")], &[], &[])
            .unwrap_err();
        assert!(!err.contains("TOKEN-SECRET"), "{err}");
    }
}
