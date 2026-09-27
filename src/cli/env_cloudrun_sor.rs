//! `op env up`'s Cloud Run SoR phase (SoRLa phase 3E), per build. The logic
//! lives in `env_sor::cloudrun` and `env_packs::gcp_cloudrun::sor`; this file
//! only chooses the targets. A build without the live Cloud Run client
//! refuses honestly instead of skipping an environment's SoR units.

use serde_json::Value;

#[cfg(feature = "creds-gcp")]
pub(crate) use super::env_sor::cloudrun::CloudRunSorRun;

/// A build without GCP support can never hold a SoR run.
#[cfg(not(feature = "creds-gcp"))]
pub(crate) enum CloudRunSorRun {}

#[cfg(all(feature = "creds-gcp", feature = "deploy-gcp-cloudrun"))]
mod live;
#[cfg(all(feature = "creds-gcp", feature = "deploy-gcp-cloudrun"))]
pub(crate) use live::{sor_finish, sor_up, teardown_sor_units};

#[cfg(not(all(feature = "creds-gcp", feature = "deploy-gcp-cloudrun")))]
pub(crate) fn sor_up(
    store: &crate::environment::LocalFsStore,
    env: &greentic_deploy_spec::Environment,
    _env_id: &greentic_deploy_spec::EnvId,
    _answers: Option<&Value>,
) -> Result<Option<CloudRunSorRun>, crate::cli::OpError> {
    let env_id = &env.environment_id;
    if store.load_sor_units(env_id)?.is_empty() && store.load_sor_ledger(env_id)?.is_empty() {
        return Ok(None);
    }
    Err(crate::cli::OpError::Conflict(
        "this build was compiled without the `deploy-gcp-cloudrun` feature; it cannot deploy \
         or retire this environment's SoR units on Cloud Run"
            .to_string(),
    ))
}

#[cfg(not(all(feature = "creds-gcp", feature = "deploy-gcp-cloudrun")))]
pub(crate) fn sor_finish(
    _store: &crate::environment::LocalFsStore,
    _env: &greentic_deploy_spec::Environment,
    _env_id: &greentic_deploy_spec::EnvId,
    _answers: Option<&Value>,
    _run: &CloudRunSorRun,
) -> Result<Vec<String>, crate::cli::OpError> {
    // `sor_up` above never returns a run in this build.
    Ok(Vec::new())
}

pub(crate) fn add_sor_result(result: &mut Value, run: &CloudRunSorRun, notes: Vec<String>) {
    #[cfg(feature = "creds-gcp")]
    super::env_sor::cloudrun::add_to_result(result, run, notes);
    #[cfg(not(feature = "creds-gcp"))]
    {
        let _ = (result, notes);
        match *run {}
    }
}

#[cfg(test)]
mod tests {
    /// `op env up` on Cloud Run: every SoR is up and its route document
    /// written BEFORE any worker is warmed (a revision keeps the seed it was
    /// created with), and retirement happens only AFTER traffic has moved.
    #[test]
    fn cloudrun_env_up_brings_sor_units_up_before_workers_and_retires_after_traffic() {
        let src = include_str!("env.rs");
        let start = src
            .find("pub(crate) fn cloudrun_env_up(")
            .expect("cloudrun_env_up exists");
        let body = &src[start..];
        let body = &body[..body.find("\n}\n").expect("end of cloudrun_env_up")];
        let at = |needle: &str| {
            body.find(needle)
                .unwrap_or_else(|| panic!("`{needle}` missing from cloudrun_env_up"))
        };
        let up = at("env_cloudrun_sor::sor_up(");
        let warm = at("cloudrun_revisions_to_warm(&env)");
        let traffic = at("apply_traffic_non_k8s(");
        let finish = at("env_cloudrun_sor::sor_finish(");
        let report = at("env_cloudrun_sor::add_sor_result(");
        assert!(
            up < warm,
            "SoR units must be up before any worker is warmed"
        );
        assert!(
            warm < traffic && traffic < finish,
            "retire only after traffic moved"
        );
        assert!(finish < report);
    }

    /// `op env destroy` must not leave a public database front-end running.
    #[test]
    fn destroy_retires_the_ledgers_cloud_run_sor_units() {
        let src = include_str!("env.rs");
        let start = src
            .find("impl crate::environment::ProviderTeardown for CloudRunProviderTeardown")
            .expect("the Cloud Run teardown exists");
        let body = &src[start..];
        let body = &body[..body.find("\n}\n").expect("end of the impl")];
        let services = body
            .find("target.delete_service(")
            .expect("worker services deleted");
        let sor = body
            .find("env_cloudrun_sor::teardown_sor_units(")
            .expect("SoR units retired on destroy");
        assert!(
            services < sor,
            "workers go first, so nothing calls a deleted SoR"
        );
    }
}
