//! CLI wiring for the `greentic.deployer.ssh-host` env-pack.
//!
//! The handler itself (`env_packs::ssh_host`) is transport- and store-agnostic:
//! it is handed the SSH target through the binding's answers, the local store
//! root and the filtered dev-store bytes. This module is the one place the CLI
//! supplies them:
//!
//! - **Binding time** ([`validate_binding_answers`], [`validate_answers_file`]):
//!   `op env-packs add|update` and `op env apply` parse the binding's answers
//!   with the same strict parser the deployer uses, so a typo is refused when
//!   the binding is written, not at the first deploy.
//! - **`op credentials requirements`** ([`connected_credentials`]): binds the
//!   answers' SSH target to the handler's credentials so the six VM probes run
//!   for real instead of failing closed with "no SSH target is bound".
//! - **`op env apply-revision` / `op env up`** ([`apply_revision`], [`env_up`]):
//!   build a handler over the env's store and drive the `Deployer` verbs.
//!
//! Nothing here reads or prints the SSH identity: `identity_file` stays a path
//! inside the answers, the handler's `Debug` redacts it and `SystemSsh` scrubs
//! it from ssh's stderr.

use std::path::Path;
use std::sync::Arc;

use greentic_deploy_spec::{
    CapabilitySlot, EnvId, EnvPackBinding, Environment, PackDescriptor, RevisionId,
};
use serde_json::{Value, json};

use super::OpError;
use super::env::{
    RevisionVerb, cloudrun_revisions_to_warm, load_render_answers, read_dev_secrets_bytes,
    resolve_live_deployer_kind, secrets_backend_is_dev_store,
};
use crate::credentials::DeployerCredentials;
use crate::env_packs::deployer::Deployer;
use crate::env_packs::ssh_host::{
    Remote, SshHostCredentials, SshHostDeployerHandler, SshHostParams, SystemSsh, WarmReport,
};
use crate::env_packs::{EnvPackRegistry, k8s::async_bridge::run_k8s_async};
use crate::environment::{EnvironmentStore as _, LocalFsStore};

/// Whether `descriptor` is the ssh-host deployer kind (any version).
pub(crate) fn is_ssh_host_kind(descriptor: &PackDescriptor) -> bool {
    descriptor.path() == SshHostDeployerHandler::DESCRIPTOR_PATH
}

/// The transport every CLI path uses. Production is the system `ssh`; tests in
/// this crate install a simulated VM (see [`test_remote`]).
fn remote() -> Arc<dyn Remote> {
    #[cfg(test)]
    if let Some(fake) = test_remote::current() {
        return fake;
    }
    Arc::new(SystemSsh::new())
}

#[cfg(test)]
pub(crate) mod test_remote {
    //! Per-thread transport override so a CLI-level test can run the whole verb
    //! (which builds its own handler) against a simulated VM. Per thread, so
    //! parallel tests cannot see each other's VM.

    use std::cell::RefCell;
    use std::sync::Arc;

    use crate::env_packs::ssh_host::Remote;

    thread_local! {
        static OVERRIDE: RefCell<Option<Arc<dyn Remote>>> = const { RefCell::new(None) };
    }

    pub(crate) fn current() -> Option<Arc<dyn Remote>> {
        OVERRIDE.with(|slot| slot.borrow().clone())
    }

    /// Route every ssh-host CLI call on this thread to `remote` until dropped.
    pub(crate) fn install(remote: Arc<dyn Remote>) -> Guard {
        OVERRIDE.with(|slot| *slot.borrow_mut() = Some(remote));
        Guard
    }

    pub(crate) struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            OVERRIDE.with(|slot| *slot.borrow_mut() = None);
        }
    }
}

fn invalid_answers(e: impl std::fmt::Display) -> OpError {
    OpError::Conflict(format!("invalid ssh-host binding answers: {e}"))
}

/// Parse the binding's answers for `env`. `None` answers is an error: an SSH
/// target cannot be defaulted.
fn params_from(env: &Environment, answers: Option<&Value>) -> Result<SshHostParams, OpError> {
    let answers = answers.ok_or_else(|| {
        OpError::Conflict(
            "the ssh-host deployer binding records no answers (`answers_ref`); it needs at \
             least `host` and `user`. Bind them with `op env-packs update` (payload \
             `answers_ref`) or the `packs[].answers` of an env manifest"
                .to_string(),
        )
    })?;
    SshHostParams::from_answers(env, answers).map_err(invalid_answers)
}

/// `op env-packs add|update`: when the binding is the ssh-host deployer and
/// names an `answers_ref`, read that file (it must live under the env dir, like
/// every binding answers file) and refuse the binding if the answers do not
/// parse. A binding without `answers_ref` is allowed (it can be updated later);
/// the verbs that need an SSH target refuse it then.
pub(crate) fn validate_binding_answers(
    store: &LocalFsStore,
    env_id: &EnvId,
    binding: &EnvPackBinding,
) -> Result<(), OpError> {
    if binding.slot != CapabilitySlot::Deployer || !is_ssh_host_kind(&binding.kind) {
        return Ok(());
    }
    let Some(rel_path) = binding.answers_ref.as_deref() else {
        return Ok(());
    };
    let env = store.load(env_id)?;
    let answers = super::env::read_binding_answers(store, &env, rel_path)?;
    params_from(&env, Some(&answers)).map(|_| ())
}

/// `op env apply`: validate a manifest pack's answers file (already resolved to
/// an existing path; inline `answers` are written to one before this runs).
/// `env_id` is the manifest's, since the environment may not exist yet.
pub(crate) fn validate_answers_file(env_id: &str, file: &Path) -> Result<(), OpError> {
    let raw = std::fs::read_to_string(file).map_err(|e| OpError::Io {
        path: file.to_path_buf(),
        source: e,
    })?;
    let answers: Value = serde_json::from_str(&raw).map_err(|e| OpError::AnswersParse {
        path: file.to_path_buf(),
        message: e.to_string(),
    })?;
    SshHostParams::from_answers_for_env_id(env_id, &answers)
        .map(|_| ())
        .map_err(invalid_answers)
}

/// `op credentials requirements`: the ssh-host credentials with the binding's
/// SSH target bound, so the probes reach the VM. `Ok(None)` for any other
/// deployer, and for an ssh-host binding that records no answers (the handler's
/// own credentials then fail closed, naming what is missing). Fails closed
/// (`Conflict`) when the recorded answers are unreadable or invalid.
pub(crate) fn connected_credentials(
    store: &LocalFsStore,
    env_id: &EnvId,
) -> Result<Option<Box<dyn DeployerCredentials>>, OpError> {
    let Ok(env) = store.load(env_id) else {
        return Ok(None);
    };
    let Some(binding) = env.pack_for_slot(CapabilitySlot::Deployer) else {
        return Ok(None);
    };
    if !is_ssh_host_kind(&binding.kind) {
        return Ok(None);
    }
    let (answers, _wire) = load_render_answers(store, &env, &binding.kind)?;
    let Some(answers) = answers else {
        return Ok(None);
    };
    let params = params_from(&env, Some(&answers))?;
    Ok(Some(Box::new(SshHostCredentials::with_target(
        remote(),
        params,
    ))))
}

/// A handler over the env's store: the transport, the store root, and the
/// dev-store bytes (filtered by `read_dev_secrets_bytes`, which strips the
/// deployer's own bound credential) when the env's secrets backend is the
/// dev-store. A Vault-backed env ships no dev-store: it would carry
/// operator-local material to the VM.
fn handler_for(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
    ship_store: bool,
) -> Result<SshHostDeployerHandler, OpError> {
    let handler = SshHostDeployerHandler::with_remote(remote(), None);
    if !ship_store {
        return Ok(handler);
    }
    let stages_dev_secrets = env.packs.iter().any(|p| p.slot == CapabilitySlot::Secrets)
        && secrets_backend_is_dev_store(env);
    let dev_secrets = if stages_dev_secrets {
        read_dev_secrets_bytes(store, env_id)?
    } else {
        None
    };
    Ok(handler.with_local_store(store.root().to_path_buf(), dev_secrets))
}

/// The revisions the VM serves. One service serves the whole store, so a warm
/// of any revision synchronizes all of them: the ones carrying traffic (or the
/// newest of a split-less deployment), plus the one the caller named. Using the
/// same set from `apply-revision` and `env up` keeps the two idempotent with
/// each other.
fn revisions_served(env: &Environment, named: Option<RevisionId>) -> Vec<RevisionId> {
    let mut ids: Vec<RevisionId> = cloudrun_revisions_to_warm(env)
        .iter()
        .map(|r| r.revision_id)
        .collect();
    if let Some(named) = named
        && !ids.contains(&named)
    {
        ids.push(named);
    }
    ids
}

fn conflict(e: impl std::fmt::Display) -> OpError {
    OpError::Conflict(e.to_string())
}

/// `op env apply-revision` for an ssh-host env. Mirrors the other backends:
/// returns `(identity, service name, endpoint url)`.
///
/// The identity label says how ssh authenticates, never with what.
pub(crate) fn apply_revision(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
    revision_id: RevisionId,
    verb: RevisionVerb,
    answers: Option<&Value>,
) -> Result<(&'static str, String, Option<String>), OpError> {
    let params = params_from(env, answers)?;
    let identity = identity_label(&params);
    let service = params.service_name.clone();
    let handler = handler_for(store, env, env_id, verb == RevisionVerb::Warm)?;
    let served = revisions_served(env, Some(revision_id));
    let endpoint = run_k8s_async(async {
        match verb {
            RevisionVerb::Warm => handler
                .warm_with_report(env, &served, answers)
                .await
                .map(|report| report.endpoint_url),
            RevisionVerb::Drain => handler
                .drain_revision(env, revision_id, answers)
                .await
                .map(|_| None),
            RevisionVerb::Archive => handler
                .archive_revision(env, revision_id, answers)
                .await
                .map(|_| None),
        }
    })
    .map_err(conflict)?;
    Ok((identity, service, endpoint))
}

fn identity_label(params: &SshHostParams) -> &'static str {
    if params.identity_file.is_some() {
        "ssh-identity-file"
    } else {
        "ssh-default"
    }
}

/// `op env up` for an ssh-host env: after the deployer-agnostic apply, warm the
/// VM once for every revision it serves and report the result. `Ok(None)` for
/// any other deployer so `env up` falls through to its other arms.
///
/// One warm covers the whole env: the VM runs one greentic-start serving the
/// store, so there is no per-revision rollout and no traffic split to push.
/// Idempotent: a converged VM is neither re-uploaded nor restarted
/// (`"changed": false`).
pub(crate) fn env_up(
    store: &LocalFsStore,
    registry: &EnvPackRegistry,
    env_id: &EnvId,
) -> Result<Option<Value>, OpError> {
    let env = store.load(env_id)?;
    let descriptor = resolve_live_deployer_kind(&env, None)?;
    if !is_ssh_host_kind(&descriptor) {
        return Ok(None);
    }
    registry
        .resolve_for_slot(CapabilitySlot::Deployer, &descriptor)
        .map_err(conflict)?;

    let (answers, _wire) = load_render_answers(store, &env, &descriptor)?;
    let params = params_from(&env, answers.as_ref())?;
    let served = revisions_served(&env, None);
    if served.is_empty() {
        return Err(OpError::Conflict(format!(
            "env `{env_id}` has no revision to put on the VM (none is Warming, Ready or \
             Draining); stage a bundle first with `op deploy`"
        )));
    }
    let handler = handler_for(store, &env, env_id, true)?;
    let report: WarmReport =
        run_k8s_async(handler.warm_with_report(&env, &served, answers.as_ref()))
            .map_err(conflict)?;
    Ok(Some(up_result(
        &env,
        &descriptor,
        &params,
        &served,
        &report,
    )))
}

/// The `op env up` result object. Holds no secret: the host, user-chosen paths
/// and the service name are the operator's own non-secret answers; the identity
/// file is never included.
fn up_result(
    env: &Environment,
    descriptor: &PackDescriptor,
    params: &SshHostParams,
    served: &[RevisionId],
    report: &WarmReport,
) -> Value {
    let mut result = json!({
        "environment_id": env.environment_id.as_str(),
        "kind": descriptor.as_str(),
        "host": params.host,
        "service": report.service_name,
        "install_dir": report.install_dir,
        "listen_addr": report.listen_addr,
        "store_slot": report.active_slot,
        "changed": report.changed,
        "revisions": served.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "exposed": params.expose,
    });
    if let Some(url) = &report.endpoint_url {
        result["endpoint_url"] = json!(url);
    }
    result
}

#[cfg(test)]
mod tests;
