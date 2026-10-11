//! The live half: regional Google clients behind `SorTargets`.

use std::sync::Arc;

use async_trait::async_trait;
use greentic_deploy_spec::{EnvId, Environment};
use serde_json::{Value, json};

use crate::cli::OpError;
use crate::cli::env_sor::cloudrun::{self, CloudRunSorRun, SorTargetPair, SorTargets};
use crate::env_packs::gcp_cloudrun::bound_session::GcpCredentialMaterial;
use crate::env_packs::gcp_cloudrun::credentials::run_gcp_async;
use crate::env_packs::gcp_cloudrun::deploy_target::CloudRunTarget;
use crate::env_packs::gcp_cloudrun::sor::real::RealSorTarget;
use crate::env_packs::gcp_cloudrun::sor::spec::SorReadyTiming;
use crate::env_packs::gcp_cloudrun::sor::target::SorServiceTarget;
use crate::environment::LocalFsStore;
use crate::environment::sor_units::CloudRunSorPlacement;

/// Builds clients for each place with the env's bound deployer credential,
/// else ambient ADC — the identity every other Cloud Run verb deploys as.
struct RealSorTargets {
    credentials: Option<GcpCredentialMaterial>,
}

#[async_trait]
impl SorTargets for RealSorTargets {
    async fn at(&self, project: &str, region: &str) -> Result<SorTargetPair, OpError> {
        let real = RealSorTarget::resolve(project, region, self.credentials.clone())
            .await
            .map_err(|e| {
                OpError::Conflict(format!(
                    "cannot initialize the GCP Cloud Run client for `{project}`/`{region}`: {e}"
                ))
            })?;
        let secrets: Arc<dyn CloudRunTarget> = Arc::new(real.run_target());
        let services: Arc<dyn SorServiceTarget> = Arc::new(real);
        Ok((secrets, services))
    }
}

fn nothing_to_do(store: &LocalFsStore, env_id: &EnvId) -> Result<bool, OpError> {
    Ok(store.load_sor_units(env_id)?.is_empty() && store.load_sor_ledger(env_id)?.is_empty())
}

pub(crate) fn sor_up(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
    answers: Option<&Value>,
) -> Result<Option<CloudRunSorRun>, OpError> {
    // No SoR units, now or ever: no client, no extra answers parse.
    if nothing_to_do(store, env_id)? {
        return Ok(None);
    }
    let (_identity, params, credentials) =
        crate::cli::env::cloudrun_target_inputs(store, env, env_id, answers)?;
    let backend = crate::cli::env::resolve_secrets_backend(store, env)?;
    let targets = RealSorTargets { credentials };
    run_gcp_async(cloudrun::up(
        store,
        env,
        &params,
        &backend,
        &targets,
        SorReadyTiming::from_env(),
    ))
}

pub(crate) fn sor_finish(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
    answers: Option<&Value>,
    run: &CloudRunSorRun,
) -> Result<Vec<String>, OpError> {
    let (_identity, _params, credentials) =
        crate::cli::env::cloudrun_target_inputs(store, env, env_id, answers)?;
    let targets = RealSorTargets { credentials };
    run_gcp_async(cloudrun::finish(store, env_id, run, &targets))
}

/// `op env destroy`: delete every Cloud Run SoR service and secret the ledger
/// records (ownership-checked). Runs under the destroy flock; reads the ledger
/// without taking it. `Ok(None)` when the ledger holds no SoR unit, so the
/// caller can omit the `"sor"` result key entirely rather than reporting an
/// empty object.
pub(crate) fn teardown_sor_units(
    store: &LocalFsStore,
    env_id: &EnvId,
    credentials: Option<GcpCredentialMaterial>,
) -> Result<Option<Value>, String> {
    teardown_via(store, env_id, &RealSorTargets { credentials })
}

/// [`teardown_sor_units`] against any set of regional clients.
fn teardown_via(
    store: &LocalFsStore,
    env_id: &EnvId,
    targets: &dyn SorTargets,
) -> Result<Option<Value>, String> {
    let places: Vec<CloudRunSorPlacement> = store
        .load_sor_ledger(env_id)
        .map_err(|e| format!("reading the SoR ledger: {e}"))?
        .into_iter()
        .filter_map(|a| a.cloud_run)
        .collect();
    if places.is_empty() {
        return Ok(None);
    }
    let out = run_gcp_async(cloudrun::retire_all(env_id.as_str(), &places, &[], targets))
        .map_err(|e| e.to_string())?;
    Ok(Some(json!({
        "deleted_services": out.deleted_services,
        "deleted_secrets": out.deleted_secrets,
        "notes": out.notes,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests_common::make_env;
    use crate::environment::EnvironmentStore as _;

    /// A plain Cloud Run destroy — no SoR unit ever declared for this
    /// environment — must report no `sor` result at all, not an empty
    /// object: the caller (`CloudRunProviderTeardown::teardown`) inserts the
    /// `"sor"` key only when this returns `Some`.
    use crate::environment::sor_units::AppliedSorUnit;

    /// Clients that always refuse, so a test learns whether a code path asked
    /// for a Google client at all without touching a network or ADC.
    struct RefusingTargets;

    #[async_trait]
    impl SorTargets for RefusingTargets {
        async fn at(&self, project: &str, region: &str) -> Result<SorTargetPair, OpError> {
            Err(OpError::Conflict(format!(
                "no client for {project}/{region}"
            )))
        }
    }

    fn ledger_entry() -> AppliedSorUnit {
        AppliedSorUnit {
            unit_id: "ledger".into(),
            sor: "ledger-sor".into(),
            namespace: String::new(),
            cloud_run: Some(CloudRunSorPlacement::for_unit(
                "proj",
                "europe-west1",
                "gtc-local",
                "ledger",
            )),
            input_refs: vec![],
        }
    }

    fn store_with_ledger() -> (tempfile::TempDir, LocalFsStore, Environment) {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env = make_env("local");
        store.save(&env).unwrap();
        store
            .transact(&env.environment_id, |l| {
                l.save_sor_ledger(&[ledger_entry()])
            })
            .unwrap();
        (dir, store, env)
    }

    #[test]
    fn nothing_to_do_is_true_only_with_no_units_and_no_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env = make_env("local");
        store.save(&env).unwrap();
        assert!(nothing_to_do(&store, &env.environment_id).unwrap());

        let (_d, store, env) = store_with_ledger();
        assert!(!nothing_to_do(&store, &env.environment_id).unwrap());
    }

    #[test]
    fn sor_up_builds_no_client_when_there_are_no_units() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env = make_env("local");
        store.save(&env).unwrap();
        let run = sor_up(&store, &env, &env.environment_id, None).unwrap();
        assert!(run.is_none());
    }

    #[test]
    fn teardown_reports_what_each_place_deleted() {
        // An empty ledger is covered by the test below; here the ledger names
        // one place and the clients refuse, so the failure surfaces as text.
        let (_d, store, env) = store_with_ledger();
        let err = teardown_via(&store, &env.environment_id, &RefusingTargets).unwrap_err();
        assert!(err.contains("no client for proj/europe-west1"), "{err}");
    }

    #[test]
    fn teardown_with_an_empty_ledger_asks_for_no_client() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env = make_env("local");
        store.save(&env).unwrap();
        let out = teardown_via(&store, &env.environment_id, &RefusingTargets).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn no_sor_units_ever_declared_reports_no_sor_result() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env = make_env("local");
        store.save(&env).unwrap();

        let sor = teardown_sor_units(&store, &env.environment_id, None).unwrap();

        assert!(
            sor.is_none(),
            "an environment with no SoR units must not report a `sor` key"
        );
    }
}
