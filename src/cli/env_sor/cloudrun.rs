//! The Cloud Run half of the SoR phase (SoRLa phase 3E): resolving what to
//! deploy and refusing what cannot work on Cloud Run (this task), then
//! bringing units up and retiring them (Task 9).

use std::ffi::OsString;

use greentic_deploy_spec::{CapabilitySlot, Environment};
use serde_json::Value;

use super::prepare::{PreparedSor, SorLanePlacement, prepare_inner};
use crate::cli::OpError;
use crate::cli::secrets::DEV_SECRETS_PATH_ENV;
use crate::env_packs::k8s::manifests::SecretsBackend;
use crate::env_packs::k8s::manifests::sor::SOR_PORT;
use crate::env_packs::k8s::sor_reconcile::SorUnitRender;
use crate::environment::LocalFsStore;

/// The only auth mode a publicly reachable SoR may run with (E5).
const REQUIRED_AUTH_MODE: &str = "shared_secret";

/// Resolve the Cloud Run SoR phase. `None` when nothing is declared and
/// nothing was ever deployed, so an environment without SoR units runs
/// exactly as before.
///
/// Until the CLI's live Cloud Run glue (Task 9, `deploy-gcp-cloudrun`) calls
/// this, it has no non-test caller in a `creds-gcp`-only build — allowed dead
/// there rather than forcing a premature caller in.
#[cfg_attr(not(feature = "deploy-gcp-cloudrun"), allow(dead_code))]
pub(crate) fn prepare_cloud_run(
    store: &LocalFsStore,
    env: &Environment,
    project: &str,
    region: &str,
    secret_prefix: &str,
    backend: &SecretsBackend,
) -> Result<Option<PreparedSor>, OpError> {
    prepare_cloud_run_with_override(
        store,
        env,
        project,
        region,
        secret_prefix,
        backend,
        std::env::var_os(DEV_SECRETS_PATH_ENV),
    )
}

pub(super) fn prepare_cloud_run_with_override(
    store: &LocalFsStore,
    env: &Environment,
    project: &str,
    region: &str,
    secret_prefix: &str,
    backend: &SecretsBackend,
    dev_secrets_path_override: Option<OsString>,
) -> Result<Option<PreparedSor>, OpError> {
    // Before any input is read: without a secrets pack the dev store is not
    // staged into worker seeds, so no worker could ever find a route document.
    if !store.load_sor_units(&env.environment_id)?.is_empty() {
        require_secrets_binding(env)?;
    }
    let placement = || {
        Ok(SorLanePlacement::CloudRun {
            project: project.to_string(),
            region: region.to_string(),
            secret_prefix: secret_prefix.to_string(),
        })
    };
    prepare_inner(
        store,
        env,
        &placement,
        backend,
        dev_secrets_path_override,
        &|renders| renders.iter().try_for_each(check_cloud_run_answers),
    )
}

/// On Cloud Run a worker reaches its SoR only through the route document in
/// its seed, and `op env up` stages the dev store as a seed only when the env
/// binds a `Secrets`-slot pack (`env::cloudrun_stages_dev_secrets`).
fn require_secrets_binding(env: &Environment) -> Result<(), OpError> {
    if env.pack_for_slot(CapabilitySlot::Secrets).is_some() {
        return Ok(());
    }
    Err(OpError::Conflict(format!(
        "environment `{}` declares SoR units but binds no secrets pack; on Cloud Run a worker \
         finds its SoR only through the staged dev-store seed — bind \
         `greentic.secrets.dev-store` in the manifest's `packs`",
        env.environment_id.as_str()
    )))
}

/// Cloud Run routes to and probes only the container port, and the service is
/// reachable from the internet (E5). Names the field and the expected value;
/// neither a bind address nor an auth mode is a secret.
fn check_cloud_run_answers(render: &SorUnitRender) -> Result<(), OpError> {
    let unit_id = &render.unit.unit_id;
    // `resolve_sor_inputs` already refused answers that are not a JSON object.
    let parsed: Value = serde_json::from_str(render.inputs.answers.expose()).unwrap_or(Value::Null);
    let root = parsed
        .get("answers")
        .filter(|a| a.is_object())
        .unwrap_or(&parsed);

    let bind = root.pointer("/server/bind").and_then(Value::as_str);
    let bind_ok = bind
        .and_then(|b| b.parse::<std::net::SocketAddr>().ok())
        .is_some_and(|a| a.port() == SOR_PORT && a.ip().is_unspecified());
    if !bind_ok {
        return Err(OpError::Conflict(format!(
            "SoR unit `{unit_id}`: on Cloud Run its answers must set `server.bind` to \
             `0.0.0.0:{SOR_PORT}`, the only port Cloud Run routes to and probes (found {})",
            bind.map_or_else(|| "no bind".to_string(), |b| format!("`{b}`"))
        )));
    }

    let mode = root.pointer("/server/auth/mode").and_then(Value::as_str);
    if mode != Some(REQUIRED_AUTH_MODE) {
        return Err(OpError::Conflict(format!(
            "SoR unit `{unit_id}`: on Cloud Run its service is reachable from the internet, so \
             its answers must set `server.auth.mode` to `{REQUIRED_AUTH_MODE}` (found {})",
            mode.map_or_else(|| "none".to_string(), |m| format!("`{m}`"))
        )));
    }
    Ok(())
}

#[cfg(test)]
#[path = "cloudrun_prepare_tests.rs"]
mod prepare_tests;
