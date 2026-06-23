//! `gtc op credentials {requirements,bootstrap,rotate}` (`C1`).
//!
//! Per `plans/next-gen-deployment.md` §P5, credentials are first-class with
//! two modes:
//!
//! - **requirements**: validate user-supplied minimum credentials against
//!   the deployer env-pack's declared requirements.
//! - **bootstrap**: run the deployer env-pack's bootstrap pack against
//!   ephemeral admin credentials; produce low-privilege output + a
//!   reviewable rules pack.
//! - **rotate**: re-mint the env's bound deployer credential in place
//!   (K8s `--bind` only this round) and re-persist the fresh material,
//!   leaving `credentials_ref` unchanged. `--if-needed` makes it the
//!   idempotent, schedulable form — a no-op until the current token is at
//!   80% of its lifetime — so a cron/CronJob refreshes the bound token
//!   before it lapses instead of a full re-bind.
//!
//! All three resolve the env's bound deployer env-pack through the A9
//! registry and invoke the
//! [`DeployerCredentials`](crate::credentials::DeployerCredentials) contract
//! shipped with that handler (C1). Deployer handlers that have not yet
//! registered a credentials contract surface as `HandlerNotRegistered`
//! (a structured CLI conflict, not a silent pass).
//!
//! Preconditions enforced at this layer (before audit, before delegating
//! to the registry):
//!
//! - The env must exist.
//! - The env must have a `Deployer` slot bound.
//! - For `requirements`/`rotate`, the env must already have a
//!   `credentials_ref` (the user supplied creds somewhere). For
//!   `bootstrap`, `credentials_ref` MUST be absent (bootstrap creates it).
//!
//! ## Admin credentials posture
//!
//! `bootstrap` reads the admin material via
//! [`load_admin_credential`](self::load_admin_credential), wraps it in
//! [`ZeroizedAdmin`], and never writes it to the env's storage. The
//! wrapper zeroizes the in-process buffer on drop where the language /
//! runtime allows it. The CLI does NOT claim process-wide memory erasure
//! is guaranteed — that's impossible (OS paging, cloud SDK internal
//! copies, ambient profile chains live outside this process). Operators
//! needing stronger guarantees should run bootstrap on a short-lived
//! process (CI runner, dedicated VM).

use std::path::{Path, PathBuf};

use greentic_deploy_spec::EnvId;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::credentials::{
    DeployerCredentials, RunBootstrapError, ValidateError, ZeroizedAdmin, run_bootstrap,
    validate_requirements,
};
use crate::env_packs::EnvPackRegistry;
use crate::env_packs::k8s::K8sDeployerCredentials;
use crate::environment::{EnvironmentStore, LocalFsStore};

use super::{AuditCtx, AuditGens, OpError, OpFlags, OpOutcome, audit_and_record};

const NOUN: &str = "credentials";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialsRequirementsPayload {
    pub environment_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialsBootstrapPayload {
    pub environment_id: String,
    /// Local profile name (e.g. AWS named profile) used for the one-time
    /// admin run. Never written to the env's storage.
    pub admin_profile: String,
    /// Path to a file holding the admin credential material. The
    /// contents are loaded into a [`ZeroizedAdmin`] wrapper and dropped
    /// (zeroized) before this call returns. Mutually exclusive with
    /// `admin_material_inline`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_material_path: Option<PathBuf>,
    /// Inline admin credential material — convenient for piping (e.g.
    /// `gtc op credentials bootstrap … --answers <(...)`). Never
    /// persisted by the CLI. Mutually exclusive with `admin_material_path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_material_inline: Option<String>,
    /// When `true`, the K8s deployer connects AS THE ADMIN (the
    /// `admin_profile` kubeconfig context), applies the rendered RBAC live,
    /// mints the deployer ServiceAccount's token, and binds it — instead of
    /// emitting a render-only rules pack for offline `kubectl apply`. K8s
    /// only this round; rejected for other deployers and for builds without
    /// the `k8s-client` feature.
    #[serde(default)]
    pub bind: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialsRotatePayload {
    pub environment_id: String,
    /// Local profile / kubeconfig context for the one-time admin connection
    /// that re-mints the bound credential. Rotation always re-mints AS THE
    /// ADMIN (the bound identity itself cannot create its own tokens by
    /// design). Never written to the env's storage.
    pub admin_profile: String,
    /// Path to a file holding the admin credential material (loaded into a
    /// [`ZeroizedAdmin`] and zeroized before this call returns). Mutually
    /// exclusive with `admin_material_inline`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_material_path: Option<PathBuf>,
    /// Inline admin credential material — never persisted. Mutually exclusive
    /// with `admin_material_path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_material_inline: Option<String>,
    /// When `true`, rotate ONLY if the current bound token is at/past 80% of
    /// its lifetime (kubelet's projected-token refresh point). A no-op
    /// otherwise — the idempotent form a scheduler calls on a cadence
    /// shorter than the token lifetime. When `false` (default), rotate
    /// unconditionally.
    #[serde(default)]
    pub if_needed: bool,
}

#[derive(Debug, Error)]
enum AdminLoadError {
    #[error("no admin material supplied: provide `admin_material_path` or `admin_material_inline`")]
    Missing,
    #[error("cannot supply both `admin_material_path` and `admin_material_inline`")]
    Both,
    #[error("read admin material from `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("admin material at `{path}` is not valid UTF-8")]
    NonUtf8 { path: PathBuf },
    #[error("admin material is empty")]
    Empty,
}

/// `op credentials requirements`. Resolves the env's deployer handler
/// through the registry, runs the C1 contract's probes, returns the
/// per-check report.
pub fn requirements(
    store: &LocalFsStore,
    registry: &EnvPackRegistry,
    flags: &OpFlags,
    payload: Option<CredentialsRequirementsPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "requirements", req_schema()));
    }
    let payload = resolve_payload::<CredentialsRequirementsPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;

    // For a K8s-bound env, connect a live validator client so the SSAR
    // probes run against the cluster the deployer actually targets. Other
    // deployers (and `--no-default-features` builds) get `None` and fall
    // back to the handler's own credentials probe inside the runner.
    let connected = connected_k8s_credentials(store, &env_id)?;
    let (doc, report) = validate_requirements(
        store,
        registry,
        &env_id,
        connected.as_ref().map(|c| c as &dyn DeployerCredentials),
    )
    .map_err(map_validate_err)?;

    Ok(OpOutcome::new(
        NOUN,
        "requirements",
        json!({
            "environment_id": env_id.as_str(),
            "deployer_kind": doc.deployer_kind.as_str(),
            "credentials_ref": doc.provided_credentials_ref.as_str(),
            "mode": "requirements",
            "result": result_label(&doc.validation.result),
            "missing_capabilities": doc.validation.missing_capabilities,
            "checks": report.checks,
            "last_run_at": doc.validation.last_run_at,
        }),
    ))
}

pub fn bootstrap(
    store: &LocalFsStore,
    registry: &EnvPackRegistry,
    flags: &OpFlags,
    payload: Option<CredentialsBootstrapPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "bootstrap", bootstrap_schema()));
    }
    let mut payload = resolve_payload::<CredentialsBootstrapPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let bind_requested = payload.bind;

    let admin = load_admin_credential(
        &payload.admin_profile,
        payload.admin_material_path.as_deref(),
        &mut payload.admin_material_inline,
    )
    .map_err(|e| {
        // Keep the admin-loader's specific error visible to the operator
        // — `Conflict` is the right kind for "you supplied the wrong
        // combination of options" / "the file you pointed at is empty".
        OpError::Conflict(e.to_string())
    })?;

    // `bind: true` ⇒ connect AS THE ADMIN and mint+bind the deployer's
    // ServiceAccount credential live (K8s only this round). Built before the
    // audit scope so the override outlives the `run_bootstrap` call.
    let bind_creds: Option<Box<dyn DeployerCredentials>> = if bind_requested {
        Some(
            admin_bind_k8s_credentials(store, &env_id, admin.profile())?.ok_or_else(|| {
                OpError::Conflict(
                    "`bind: true` is only supported for K8s-bound environments this round; \
                     other deployers still bootstrap a render-only rules pack — drop `bind` \
                     and apply the pack offline, then `op credentials rotate`"
                        .to_string(),
                )
            })?,
        )
    } else {
        None
    };

    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "bootstrap",
        // admin material is NEVER recorded — only the user-supplied
        // profile handle (which is not a secret) and the bind mode.
        target: json!({"admin_profile": payload.admin_profile, "bind": bind_requested}),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |committed| {
        // `run_bootstrap` holds the env flock for the entire flow:
        // load → absence check → handler.bootstrap → rules-pack write →
        // secret-material write → credentials_ref persist. No separate
        // `transact` needed here.
        let doc = match run_bootstrap(
            store,
            registry,
            &env_id,
            &admin,
            bind_creds.as_deref(),
            &dev_store_secret_sink,
        ) {
            Ok(d) => d,
            Err(e) => {
                // Compensating cleanup on the bootstrap error path: undo any
                // durable bound material written before a later step failed
                // (idempotent; no-op for non-bind deployers). See
                // `DeployerCredentials::rollback_bound_material`.
                if let Some(creds) = bind_creds.as_deref() {
                    creds.rollback_bound_material(&env_id);
                }
                return Err(map_bootstrap_err(e));
            }
        };
        committed.mark_committed();

        Ok((
            OpOutcome::new(
                NOUN,
                "bootstrap",
                json!({
                    "environment_id": env_id.as_str(),
                    "deployer_kind": doc.deployer_kind.as_str(),
                    "mode": "bootstrap",
                    "bound": bind_requested,
                    "credentials_ref": doc.provided_credentials_ref.as_str(),
                    "expires_at": doc.expiry.as_ref().map(|e| e.expires_at),
                    "rules_pack_ref": doc.bootstrap.as_ref().map(|b| b.rules_pack_ref.display().to_string()),
                    "admin_credential_consumed_at": doc.bootstrap.as_ref().map(|b| b.admin_credential_consumed_at),
                }),
            ),
            AuditGens::NONE,
        ))
    })
}

pub fn rotate(
    store: &LocalFsStore,
    registry: &EnvPackRegistry,
    flags: &OpFlags,
    payload: Option<CredentialsRotatePayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "rotate", rotate_schema()));
    }
    let mut payload = resolve_payload::<CredentialsRotatePayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let if_needed = payload.if_needed;

    // Pre-flight (before consuming admin material): the env must exist, have a
    // deployer bound, and already be bootstrapped — rotation refreshes an
    // existing bound credential, it never creates one.
    let env = store.load(&env_id).map_err(|e| match e {
        crate::environment::StoreError::NotFound(_) => {
            OpError::NotFound(format!("environment `{env_id}`"))
        }
        other => OpError::Store(other),
    })?;
    if env
        .pack_for_slot(greentic_deploy_spec::CapabilitySlot::Deployer)
        .is_none()
    {
        return Err(OpError::Conflict(format!(
            "env `{env_id}` has no deployer env-pack bound; bind one with `op env-packs add` first"
        )));
    }
    if env.credentials_ref.is_none() {
        return Err(OpError::Conflict(format!(
            "env `{env_id}` has no credentials_ref; run `op credentials bootstrap` first"
        )));
    }

    // Build the admin-connected re-mint path. Rotation always re-mints AS THE
    // ADMIN — the bound identity cannot create its own tokens by design — so a
    // non-K8s (render-only) deployer has nothing to rotate live. This only
    // constructs the connector (no connection yet), so it is cheap to run
    // before the `--if-needed` short-circuit.
    let bind_creds = admin_bind_k8s_credentials(store, &env_id, &payload.admin_profile)?
        .ok_or_else(|| {
            OpError::Conflict(
                "live rotation is only supported for K8s-bound environments this round; \
                 other deployers re-bind via `op credentials bootstrap` against a freshly \
                 applied rules pack"
                    .to_string(),
            )
        })?;

    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "rotate",
        // Admin material is NEVER recorded — only the (non-secret) profile
        // handle and the mode.
        target: json!({"admin_profile": payload.admin_profile, "if_needed": if_needed}),
        idempotency_key: None,
    };
    // EVERY outcome — including the `--if-needed` no-op — runs inside
    // `audit_and_record` so the local-only authorization gate AND the audit
    // append cover all of them. Returning the no-op before this boundary would
    // let a non-local env probe token freshness unauthorized and unaudited.
    audit_and_record(store, ctx, |committed| {
        // `--if-needed`: skip the re-mint (and never load admin material)
        // unless the current bound token is at/past 80% of its lifetime.
        // Resolves the bearer from env-var / dev-store (no cluster round-trip);
        // an unresolvable token falls through to rotate (fail-open).
        if if_needed
            && let Ok(Some(bearer)) =
                super::secrets::resolve_credentials_token(store, &env, &env_id)
            && !crate::credentials::rotation_due(&bearer, chrono::Utc::now())
        {
            return Ok((
                OpOutcome::new(
                    NOUN,
                    "rotate",
                    json!({
                        "environment_id": env_id.as_str(),
                        "rotated": false,
                        "reason": "current token has not reached its rotation threshold (80% of lifetime)",
                    }),
                ),
                AuditGens::NONE,
            ));
        }

        let admin = load_admin_credential(
            &payload.admin_profile,
            payload.admin_material_path.as_deref(),
            &mut payload.admin_material_inline,
        )
        .map_err(|e| OpError::Conflict(e.to_string()))?;

        let outcome = crate::credentials::run_rotate(
            store,
            registry,
            &env_id,
            &admin,
            bind_creds.as_ref(),
            &dev_store_secret_sink,
        )
        .map_err(map_rotate_err)?;
        committed.mark_committed();
        Ok((
            OpOutcome::new(
                NOUN,
                "rotate",
                json!({
                    "environment_id": env_id.as_str(),
                    "rotated": true,
                    "credentials_ref": outcome.credentials_ref.as_str(),
                    "expires_at": outcome.expiry.as_ref().map(|e| e.expires_at),
                    "rotate_at": outcome.expiry.as_ref().and_then(|e| e.rotate_at),
                }),
            ),
            AuditGens::NONE,
        ))
    })
}

// --- internals -----------------------------------------------------------

fn result_label(r: &greentic_deploy_spec::CredentialsValidationResult) -> &'static str {
    match r {
        greentic_deploy_spec::CredentialsValidationResult::Pass => "pass",
        greentic_deploy_spec::CredentialsValidationResult::Fail => "fail",
    }
}

/// Load admin credential material into a [`ZeroizedAdmin`] wrapper.
///
/// Takes `&mut` so the inline path can `std::mem::take` the material out
/// of the payload, leaving `None` behind — explicit single-use semantics
/// that prevents the caller from accidentally retaining the cleartext.
///
/// File path: reads into `Zeroizing<Vec<u8>>`, then converts via strict
/// `String::from_utf8` (not lossy — lossy substitution silently corrupts
/// credentials). The intermediate `Vec<u8>` is zeroized on drop.
fn load_admin_credential(
    admin_profile: &str,
    admin_material_path: Option<&Path>,
    admin_material_inline: &mut Option<String>,
) -> Result<ZeroizedAdmin, AdminLoadError> {
    match (admin_material_path, admin_material_inline.as_ref()) {
        (None, None) => Err(AdminLoadError::Missing),
        (Some(_), Some(_)) => Err(AdminLoadError::Both),
        (Some(path), None) => {
            let mut bytes =
                Zeroizing::new(std::fs::read(path).map_err(|source| AdminLoadError::Io {
                    path: path.to_path_buf(),
                    source,
                })?);
            // Take the raw bytes out of the Zeroizing wrapper. The
            // wrapper drops with an empty Vec (no-op zeroize); the
            // bytes move into String::from_utf8. On UTF-8 success the
            // String takes ownership of the same allocation; on failure
            // the bytes are returned inside the error and dropped here.
            let raw = std::mem::take(&mut *bytes);
            let material = String::from_utf8(raw).map_err(|_| AdminLoadError::NonUtf8 {
                path: path.to_path_buf(),
            })?;
            if material.trim().is_empty() {
                return Err(AdminLoadError::Empty);
            }
            Ok(ZeroizedAdmin::new(admin_profile, material))
        }
        (None, Some(_)) => {
            // Take the inline material out of the option — it becomes
            // `None` after extraction, enforcing single-use.
            let taken = admin_material_inline
                .take()
                .expect("matched Some branch; take cannot be None");
            if taken.trim().is_empty() {
                return Err(AdminLoadError::Empty);
            }
            Ok(ZeroizedAdmin::new(admin_profile, taken))
        }
    }
}

// Shared message helpers — both mappers below enrich the library-level
// error with operator-action guidance (e.g. "bind one with `op env-packs
// add` first"). The source `#[error(...)]` strings on `ValidateError` /
// `RunBootstrapError` are deliberately library-shaped (no CLI verb hints),
// so the CLI mapper layer owns the operator-facing wording.
fn no_deployer_bound_msg(env_id: &EnvId) -> String {
    format!("env `{env_id}` has no deployer env-pack bound; bind one with `op env-packs add` first")
}

fn handler_not_registered_msg(kind: &str) -> String {
    format!(
        "deployer env-pack `{kind}` has no native credentials handler registered (Phase D plug-in)"
    )
}

fn map_validate_err(e: ValidateError) -> OpError {
    match e {
        ValidateError::NoDeployerBound(env_id) => OpError::Conflict(no_deployer_bound_msg(&env_id)),
        ValidateError::NoCredentialsRef(env_id) => OpError::Conflict(format!(
            "env `{env_id}` has no credentials_ref; run `op credentials bootstrap` first"
        )),
        ValidateError::HandlerNotRegistered { kind } => {
            OpError::Conflict(handler_not_registered_msg(&kind))
        }
        ValidateError::Store(s) => OpError::Store(s),
        ValidateError::Registry(r) => OpError::Conflict(r.to_string()),
    }
}

/// Connect a live [`K8sValidatorClient`](crate::env_packs::k8s::K8sValidatorClient)
/// for a K8s-bound env so `op credentials requirements` runs its
/// `SelfSubjectAccessReview` probes against the cluster the deployer
/// actually targets.
///
/// Returns `Ok(None)` for any non-K8s deployer (the runner falls back to
/// the handler's own credentials) and for `--no-default-features` builds
/// that lack the `k8s-client` feature. Fails closed (`Conflict`) when the
/// binding's answers are unreadable or the cluster cannot be reached — the
/// same posture as `op env reconcile`. The env's `credentials_ref` is
/// resolved to a ServiceAccount bearer (identical to `reconcile` /
/// `apply-revision`): a bound token authenticates the probe as that
/// ServiceAccount, so the SSAR sweep reflects the deployer's real RBAC, not
/// the ambient admin's; `None` → the ambient kubeconfig / in-cluster identity.
#[cfg(feature = "k8s-client")]
fn connected_k8s_credentials(
    store: &LocalFsStore,
    env_id: &EnvId,
) -> Result<Option<K8sDeployerCredentials>, OpError> {
    use crate::cli::env::load_render_answers;
    use crate::env_packs::k8s::K8sDeployerHandler;
    use crate::env_packs::k8s::credentials::{
        K8sValidatorClient, K8sValidatorConnectFut, K8sValidatorConnector,
    };
    use crate::env_packs::k8s::kube_client::{KubeValidatorClient, connect};
    use crate::env_packs::k8s::manifests::{K8sParams, kubeconfig_context_from_answers};
    use std::sync::Arc;

    // If the env can't even be loaded, leave it to the runner to surface
    // the proper NotFound / store error.
    let Ok(env) = store.load(env_id) else {
        return Ok(None);
    };
    let Some(binding) = env.pack_for_slot(greentic_deploy_spec::CapabilitySlot::Deployer) else {
        return Ok(None);
    };
    if binding.kind.path() != K8sDeployerHandler::DESCRIPTOR_PATH {
        return Ok(None);
    }

    // Fail closed if the recorded answers are broken (mirrors render /
    // reconcile); a K8s env with no answers connects to the ambient
    // context.
    let (answers, _wire) = load_render_answers(store, &env, &binding.kind)?;
    let kubeconfig_context = kubeconfig_context_from_answers(answers.as_ref());
    // Probe the SAME namespace reconcile / apply-revision deploy into — the
    // answers may override the env-derived default.
    let namespace = K8sParams::from_answers(&env, answers.as_ref())
        .map_err(|e| OpError::Conflict(format!("invalid K8s answers: {e}")))?
        .namespace;
    // Resolve the env's bound deployer credential to a ServiceAccount bearer so
    // the probe authenticates as the deployer's identity, not the ambient
    // admin. `None` → ambient (no bound credential); fail-closed if a ref is
    // bound but unresolvable. Beyond env-var / dev-store, the resolver reads
    // the durable in-cluster identity Secret (ambient) as a last resort.
    let bound_token =
        crate::env_packs::k8s::resolve_bound_identity(store, &env, env_id, answers.as_ref())?;
    // Defer the connect into the probe runtime instead of connecting here: a
    // kube::Client's tower Buffer worker is bound to the runtime that spawned
    // it, and `run_k8s_async` drops its runtime after each call, so a client
    // connected in this (separate) bridge call would reach `validate` with a
    // dead worker. The connector runs connect + probes on one runtime.
    let connector: K8sValidatorConnector = Arc::new(move || -> K8sValidatorConnectFut {
        let kubeconfig_context = kubeconfig_context.clone();
        let bound_token = bound_token.clone();
        Box::pin(async move {
            let client = connect(kubeconfig_context.as_deref(), bound_token.as_deref()).await?;
            Ok(Arc::new(KubeValidatorClient::new(client)) as Arc<dyn K8sValidatorClient>)
        })
    });
    Ok(Some(
        K8sDeployerCredentials::with_connector(connector).in_namespace(namespace),
    ))
}

/// `k8s-client`-less builds cannot connect a validator; the runner falls
/// back to the handler's (fail-closed) default credentials.
#[cfg(not(feature = "k8s-client"))]
fn connected_k8s_credentials(
    _store: &LocalFsStore,
    _env_id: &EnvId,
) -> Result<Option<K8sDeployerCredentials>, OpError> {
    Ok(None)
}

/// Build admin-connected K8s credentials for the `--bind` bootstrap path:
/// a bootstrap connector that authenticates AS THE ADMIN (the
/// `admin_profile` kubeconfig context, no bound SA token) and applies the
/// rendered RBAC + mints the deployer ServiceAccount's token. Returns
/// `None` when the env is not K8s-bound (the caller rejects `--bind` for
/// other deployers). Boxed as `dyn DeployerCredentials` so the runner's
/// `creds_override` seam stays deployer-agnostic.
#[cfg(feature = "k8s-client")]
fn admin_bind_k8s_credentials(
    store: &LocalFsStore,
    env_id: &EnvId,
    admin_profile: &str,
) -> Result<Option<Box<dyn DeployerCredentials>>, OpError> {
    use crate::cli::env::load_render_answers;
    use crate::env_packs::k8s::K8sDeployerHandler;
    use crate::env_packs::k8s::credentials::{
        K8sBootstrapClient, K8sBootstrapConnectFut, K8sBootstrapConnector, K8sDeployerCredentials,
    };
    use crate::env_packs::k8s::kube_client::{KubeBootstrapClient, connect};
    use crate::env_packs::k8s::manifests::K8sParams;
    use std::sync::Arc;

    // Not loadable / no deployer bound / non-K8s ⇒ `None`; the runner (or
    // the caller's `--bind` guard) surfaces the proper error.
    let Ok(env) = store.load(env_id) else {
        return Ok(None);
    };
    let Some(binding) = env.pack_for_slot(greentic_deploy_spec::CapabilitySlot::Deployer) else {
        return Ok(None);
    };
    if binding.kind.path() != K8sDeployerHandler::DESCRIPTOR_PATH {
        return Ok(None);
    }

    // Resolve the namespace reconcile / requirements actually use (the
    // binding answers' `K8sParams::namespace`, falling back to the
    // env-derived default) and scope the bind there — applying RBAC + minting
    // the token in `gtc-<env>` while reconcile deploys into a custom namespace
    // would RoleBind the token in the wrong place. Same resolution as
    // `connected_k8s_credentials`.
    let (answers, _wire) = load_render_answers(store, &env, &binding.kind)?;
    let namespace = K8sParams::from_answers(&env, answers.as_ref())
        .map_err(|e| OpError::Conflict(format!("invalid K8s answers: {e}")))?
        .namespace;

    let admin_context = admin_profile.to_string();
    let connector: K8sBootstrapConnector = Arc::new(move || -> K8sBootstrapConnectFut {
        let admin_context = admin_context.clone();
        Box::pin(async move {
            // Authenticate as the admin kubeconfig context (no bound token);
            // that identity must hold rights to create the SA/Role/
            // RoleBinding and call the TokenRequest subresource.
            let client = connect(Some(&admin_context), None).await?;
            Ok(Arc::new(KubeBootstrapClient::new(client)) as Arc<dyn K8sBootstrapClient>)
        })
    });
    Ok(Some(Box::new(
        K8sDeployerCredentials::with_bootstrap_connector(connector).in_namespace(namespace),
    )))
}

/// `k8s-client`-less builds cannot connect a bind client — `--bind` is a
/// hard error rather than a silent fall-through to render-only.
#[cfg(not(feature = "k8s-client"))]
fn admin_bind_k8s_credentials(
    _store: &LocalFsStore,
    _env_id: &EnvId,
    _admin_profile: &str,
) -> Result<Option<Box<dyn DeployerCredentials>>, OpError> {
    Err(OpError::Conflict(
        "`bind: true` requires a build with the `k8s-client` feature".to_string(),
    ))
}

/// Dev-store sink shared by `bootstrap` and `rotate`: persists minted bearer
/// material at the location `resolve_credentials_token` reads it back from.
/// Passed as the [`BoundSecretSink`](crate::credentials::BoundSecretSink) the
/// runner invokes inside the env flock.
fn dev_store_secret_sink(
    env_root: &Path,
    secret_ref: &greentic_deploy_spec::SecretRef,
    value: &str,
) -> Result<(), String> {
    super::secrets::put_credential_material(env_root, secret_ref, value).map_err(|e| e.to_string())
}

fn map_bootstrap_err(e: RunBootstrapError) -> OpError {
    use crate::credentials::BootstrapError;
    match e {
        RunBootstrapError::NoDeployerBound(env_id) => {
            OpError::Conflict(no_deployer_bound_msg(&env_id))
        }
        RunBootstrapError::AlreadyBootstrapped(env_id) => OpError::Conflict(format!(
            "env `{env_id}` already has credentials_ref; use `rotate` instead of `bootstrap`"
        )),
        RunBootstrapError::HandlerNotRegistered { kind } => {
            OpError::Conflict(handler_not_registered_msg(&kind))
        }
        RunBootstrapError::Store(s) => OpError::Store(s),
        RunBootstrapError::Registry(r) => OpError::Conflict(r.to_string()),
        RunBootstrapError::Bootstrap(BootstrapError::NotApplicable(msg)) => OpError::Conflict(msg),
        RunBootstrapError::Bootstrap(BootstrapError::AdminRejected(msg)) => {
            OpError::Conflict(format!("admin credential rejected: {msg}"))
        }
        RunBootstrapError::Bootstrap(BootstrapError::ProvisioningFailed { step, message }) => {
            OpError::Conflict(format!("bootstrap failed during {step}: {message}"))
        }
        RunBootstrapError::RulesExport(r) => OpError::Conflict(format!("rules export: {r}")),
        RunBootstrapError::SecretWrite(msg) => OpError::Conflict(format!(
            "failed to persist bound credential material: {msg}"
        )),
    }
}

fn map_rotate_err(e: crate::credentials::RunRotateError) -> OpError {
    use crate::credentials::{BootstrapError, RunRotateError as E};
    match e {
        E::NoDeployerBound(env_id) => OpError::Conflict(no_deployer_bound_msg(&env_id)),
        E::NotBootstrapped(env_id) => OpError::Conflict(format!(
            "env `{env_id}` has no credentials_ref; run `op credentials bootstrap` first"
        )),
        E::RotationUnsupported(msg) => OpError::Conflict(msg),
        E::Store(s) => OpError::Store(s),
        E::Registry(r) => OpError::Conflict(r.to_string()),
        E::Bootstrap(BootstrapError::NotApplicable(msg)) => OpError::Conflict(msg),
        E::Bootstrap(BootstrapError::AdminRejected(msg)) => {
            OpError::Conflict(format!("admin credential rejected: {msg}"))
        }
        E::Bootstrap(BootstrapError::ProvisioningFailed { step, message }) => {
            OpError::Conflict(format!("rotation failed during {step}: {message}"))
        }
        E::SecretWrite(msg) => OpError::Conflict(format!(
            "failed to persist rotated credential material: {msg}"
        )),
    }
}

fn resolve_payload<T: serde::de::DeserializeOwned>(
    flags: &OpFlags,
    payload: Option<T>,
) -> Result<T, OpError> {
    if let Some(p) = payload {
        return Ok(p);
    }
    if let Some(path) = &flags.answers {
        return super::load_answers::<T>(path);
    }
    Err(OpError::InvalidArgument(
        "no payload provided: pass --answers <path> or supply the payload directly".to_string(),
    ))
}

fn parse_env_id(raw: &str) -> Result<EnvId, OpError> {
    EnvId::try_from(raw).map_err(|e| OpError::InvalidArgument(format!("environment_id: {e}")))
}

fn req_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "CredentialsRequirementsPayload",
        "type": "object",
        "required": ["environment_id"],
        "additionalProperties": false,
        "properties": {"environment_id": {"type": "string"}}
    })
}

fn bootstrap_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "CredentialsBootstrapPayload",
        "type": "object",
        "required": ["environment_id", "admin_profile"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "admin_profile": {"type": "string"},
            "admin_material_path": {"type": "string", "description": "path to a file holding the admin credential material (zeroized on drop)"},
            "admin_material_inline": {"type": "string", "description": "inline admin credential material (zeroized on drop); mutually exclusive with admin_material_path"},
            "bind": {"type": "boolean", "description": "K8s only: connect as the admin (admin_profile kubeconfig context), apply the RBAC live, mint + bind the ServiceAccount token instead of emitting a render-only rules pack"}
        }
    })
}

fn rotate_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "CredentialsRotatePayload",
        "type": "object",
        "required": ["environment_id", "admin_profile"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "admin_profile": {"type": "string", "description": "kubeconfig context / admin identity that re-mints the bound credential (never persisted)"},
            "admin_material_path": {"type": "string", "description": "path to a file holding the admin credential material (zeroized on drop); mutually exclusive with admin_material_inline"},
            "admin_material_inline": {"type": "string", "description": "inline admin credential material (zeroized on drop); mutually exclusive with admin_material_path"},
            "if_needed": {"type": "boolean", "description": "rotate only if the current bound token is at/past 80% of its lifetime; a no-op otherwise (the idempotent form a scheduler calls)"}
        }
    })
}

// Backwards-compat shim so existing dispatch sites that call into the
// 3-arg form (without an explicit registry) still build. Callers that
// don't yet pass a registry get the built-in set (5 default `local`
// handlers); Phase D registers more through `EnvPackRegistry::register`.
//
// Kept private — `dispatch::dispatch_credentials` is updated to pass a
// registry explicitly. Tests use this shim for convenience.
#[cfg(test)]
pub(crate) fn requirements_default(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<CredentialsRequirementsPayload>,
) -> Result<OpOutcome, OpError> {
    requirements(store, &EnvPackRegistry::with_builtins(), flags, payload)
}

#[cfg(test)]
pub(crate) fn bootstrap_default(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<CredentialsBootstrapPayload>,
) -> Result<OpOutcome, OpError> {
    bootstrap(store, &EnvPackRegistry::with_builtins(), flags, payload)
}

#[cfg(test)]
pub(crate) fn rotate_default(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<CredentialsRotatePayload>,
) -> Result<OpOutcome, OpError> {
    rotate(store, &EnvPackRegistry::with_builtins(), flags, payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests_common::{make_binding, make_env};
    use crate::environment::EnvironmentStore;
    use greentic_deploy_spec::{CapabilitySlot, SecretRef};
    use tempfile::tempdir;

    #[test]
    fn requirements_rejects_env_without_deployer() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let err = requirements_default(
            &store,
            &OpFlags::default(),
            Some(CredentialsRequirementsPayload {
                environment_id: "local".to_string(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    /// A no-material deployer (like local-process) passes requirements
    /// even without a `credentials_ref` on the env.
    #[test]
    fn requirements_passes_for_no_material_deployer_without_credentials_ref() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.local-process@0.1.0",
        ));
        store.save(&env).unwrap();
        let outcome = requirements_default(
            &store,
            &OpFlags::default(),
            Some(CredentialsRequirementsPayload {
                environment_id: "local".to_string(),
            }),
        )
        .unwrap();
        assert_eq!(outcome.result["mode"], "requirements");
        assert_eq!(outcome.result["result"], "pass");
    }

    /// The live-validator wiring only fires for a K8s-bound deployer: any
    /// other deployer yields `None` and the runner falls back to the
    /// handler's own probe (so this path never opens a socket for, e.g.,
    /// local-process).
    #[cfg(feature = "k8s-client")]
    #[test]
    fn connected_k8s_credentials_is_none_for_non_k8s_deployer() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.local-process@0.1.0",
        ));
        store.save(&env).unwrap();
        let got = connected_k8s_credentials(&store, &EnvId::try_from("local").unwrap())
            .expect("non-K8s detection never errors");
        assert!(
            got.is_none(),
            "non-K8s deployer must not connect a validator client"
        );
    }

    /// With no native credentials handler registered for the bound
    /// deployer, the CLI surfaces a structured `Conflict` (not a silent
    /// pass-through). C2 wires the local-process handler so this case
    /// passes; here we exercise an arbitrary deployer kind to confirm
    /// the "no handler" path.
    #[test]
    fn requirements_with_unregistered_deployer_kind_yields_conflict() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            // No handler is registered for this fictional kind — the
            // registry's built-in set covers local-process (C2) and (when
            // `creds-aws` is on) aws-ecs (C3). A bare fictional kind
            // exercises the resolve-failure path without depending on
            // which env-packs are or aren't registered today.
            "acme.deployer.fictional@1.0.0",
        ));
        env.credentials_ref = Some(SecretRef::try_new("secret://local/credentials/aws").unwrap());
        store.save(&env).unwrap();
        let err = requirements_default(
            &store,
            &OpFlags::default(),
            Some(CredentialsRequirementsPayload {
                environment_id: "local".to_string(),
            }),
        )
        .unwrap_err();
        // The deployer kind isn't registered → registry resolve fails
        // with `Unknown(kind)`; map_validate_err converts that to a
        // Conflict carrying the registry message.
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn bootstrap_rejects_when_creds_already_set() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.aws-ecs@1.0.0",
        ));
        env.credentials_ref = Some(SecretRef::try_new("secret://local/credentials/aws").unwrap());
        store.save(&env).unwrap();
        let err = bootstrap_default(
            &store,
            &OpFlags::default(),
            Some(CredentialsBootstrapPayload {
                environment_id: "local".to_string(),
                admin_profile: "admin".to_string(),
                admin_material_path: None,
                admin_material_inline: Some("ADMIN_TOKEN".to_string()),
                bind: false,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn bootstrap_requires_admin_material() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.aws-ecs@1.0.0",
        ));
        store.save(&env).unwrap();
        let err = bootstrap_default(
            &store,
            &OpFlags::default(),
            Some(CredentialsBootstrapPayload {
                environment_id: "local".to_string(),
                admin_profile: "admin".to_string(),
                admin_material_path: None,
                admin_material_inline: None,
                bind: false,
            }),
        )
        .unwrap_err();
        assert!(
            matches!(err, OpError::Conflict(ref m) if m.contains("no admin material")),
            "got {err:?}"
        );
    }

    #[test]
    fn bootstrap_rejects_both_path_and_inline() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.aws-ecs@1.0.0",
        ));
        store.save(&env).unwrap();
        let err = bootstrap_default(
            &store,
            &OpFlags::default(),
            Some(CredentialsBootstrapPayload {
                environment_id: "local".to_string(),
                admin_profile: "admin".to_string(),
                admin_material_path: Some("/tmp/x".into()),
                admin_material_inline: Some("y".into()),
                bind: false,
            }),
        )
        .unwrap_err();
        assert!(
            matches!(err, OpError::Conflict(ref m) if m.contains("cannot supply both")),
            "got {err:?}"
        );
    }

    /// C2 end-to-end: a fully-configured `local` env with the C2
    /// LocalProcessDeployerHandler bound returns a structured pass
    /// report for both capabilities. Exercises the full chain:
    /// CLI → registry → DeployerCredentials → probes → OpOutcome.
    #[test]
    fn requirements_against_c2_local_process_handler_returns_pass() {
        use crate::defaults::LOCAL_DEPLOYER_PACK;

        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs
            .push(make_binding(CapabilitySlot::Deployer, LOCAL_DEPLOYER_PACK));
        env.credentials_ref =
            Some(SecretRef::try_new("secret://local/credentials/local-process").unwrap());
        store.save(&env).unwrap();

        // Pick a high port range that's almost certainly free on a test
        // runner — same trick the C2 unit tests use.
        let registry = {
            let mut r = EnvPackRegistry::new();
            for h in crate::env_packs::BUILTIN_HANDLERS {
                r.register(Box::new(*h)).unwrap();
            }
            r.register(Box::new(
                crate::env_packs::LocalProcessDeployerHandler::with_port_range(49000..=49100),
            ))
            .unwrap();
            r
        };

        let outcome = requirements(
            &store,
            &registry,
            &OpFlags::default(),
            Some(CredentialsRequirementsPayload {
                environment_id: "local".to_string(),
            }),
        )
        .expect("requirements should succeed against c2 local-process");
        assert_eq!(outcome.op, "requirements");
        assert_eq!(outcome.noun, NOUN);
        assert_eq!(outcome.result["result"], "pass");
        assert!(
            outcome.result["missing_capabilities"]
                .as_array()
                .map(|a| a.is_empty())
                .unwrap_or(false),
            "no missing caps; got {outcome:?}"
        );
        let checks = outcome.result["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 2);
    }

    /// C2 end-to-end: bootstrap against local-process refuses with
    /// `NotApplicable`, surfaced as `OpError::Conflict` and recorded in
    /// the audit log.
    #[test]
    fn bootstrap_against_c2_local_process_handler_refuses_as_not_applicable() {
        use crate::defaults::LOCAL_DEPLOYER_PACK;

        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs
            .push(make_binding(CapabilitySlot::Deployer, LOCAL_DEPLOYER_PACK));
        store.save(&env).unwrap();

        let err = bootstrap_default(
            &store,
            &OpFlags::default(),
            Some(CredentialsBootstrapPayload {
                environment_id: "local".to_string(),
                admin_profile: "admin".to_string(),
                admin_material_path: None,
                admin_material_inline: Some("any-admin-token".to_string()),
                bind: false,
            }),
        )
        .unwrap_err();
        match err {
            OpError::Conflict(msg) => {
                assert!(
                    msg.contains("no admin escalation") || msg.contains("requirements"),
                    "Conflict message should point user at `requirements`, got: {msg}"
                );
            }
            other => panic!("expected Conflict (NotApplicable mapped), got {other:?}"),
        }
        // The reload-into-env step never happened: credentials_ref stays None.
        let reloaded = store.load(&"local".try_into().unwrap()).unwrap();
        assert!(reloaded.credentials_ref.is_none());
    }

    /// Build a rotate payload with the admin handle filled in (rotation
    /// always re-mints as the admin); material is omitted because the
    /// rejection paths under test short-circuit before it is consumed.
    fn rotate_payload(env_id: &str) -> CredentialsRotatePayload {
        CredentialsRotatePayload {
            environment_id: env_id.to_string(),
            admin_profile: "admin-ctx".to_string(),
            admin_material_path: None,
            admin_material_inline: None,
            if_needed: false,
        }
    }

    #[test]
    fn rotate_rejects_env_without_credentials_ref() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.aws-ecs@1.0.0",
        ));
        store.save(&env).unwrap();
        let err =
            rotate_default(&store, &OpFlags::default(), Some(rotate_payload("local"))).unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    /// Live rotation is K8s-only: a non-K8s (render-only) deployer that IS
    /// bootstrapped is rejected with a Conflict directing the operator to
    /// re-bind via `bootstrap` (no misleading success, no re-mint attempt).
    #[test]
    fn rotate_rejects_non_k8s_deployer() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.local-process@0.1.0",
        ));
        env.credentials_ref = Some(SecretRef::try_new("secret://local/credentials/test").unwrap());
        store.save(&env).unwrap();
        let err =
            rotate_default(&store, &OpFlags::default(), Some(rotate_payload("local"))).unwrap_err();
        assert!(
            matches!(err, OpError::Conflict(_)),
            "non-K8s rotation must be a Conflict, got {err:?}"
        );
    }

    /// A no-material deployer handler works against an env with no
    /// `credentials_ref` — the validate_requirements runner uses a
    /// sentinel ref instead of rejecting with NoCredentialsRef.
    #[test]
    fn no_material_deployer_requirements_without_credentials_ref() {
        use crate::credentials::{
            BootstrapError, BootstrapInput, BootstrapOutcome, Capability, DeployerCredentials,
            RequirementsReport, ValidationContext,
        };
        use crate::env_packs::EnvPackHandler;

        #[derive(Debug)]
        struct NoMaterialHandler;

        impl EnvPackHandler for NoMaterialHandler {
            fn slot(&self) -> CapabilitySlot {
                CapabilitySlot::Deployer
            }
            fn descriptor_path(&self) -> &str {
                "test.deployer.no-material"
            }
            fn supported_versions(&self) -> semver::VersionReq {
                "^0.1.0".parse().unwrap()
            }
            fn deployer_credentials(&self) -> Option<&dyn DeployerCredentials> {
                Some(&NoMaterialCreds)
            }
        }

        #[derive(Debug)]
        struct NoMaterialCreds;

        impl DeployerCredentials for NoMaterialCreds {
            fn requires_credentials_material(&self) -> bool {
                false
            }
            fn required_capabilities(&self) -> Vec<Capability> {
                Vec::new()
            }
            fn validate(&self, _ctx: &ValidationContext<'_>) -> RequirementsReport {
                RequirementsReport::new(Vec::new())
            }
            fn bootstrap(
                &self,
                _input: &BootstrapInput<'_>,
            ) -> Result<BootstrapOutcome, BootstrapError> {
                Err(BootstrapError::NotApplicable(
                    "no admin escalation".to_string(),
                ))
            }
        }

        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "test.deployer.no-material@0.1.0",
        ));
        // No credentials_ref set.
        store.save(&env).unwrap();

        let mut registry = EnvPackRegistry::new();
        registry.register(Box::new(NoMaterialHandler)).unwrap();

        let outcome = requirements(
            &store,
            &registry,
            &OpFlags::default(),
            Some(CredentialsRequirementsPayload {
                environment_id: "local".to_string(),
            }),
        )
        .unwrap();
        assert_eq!(outcome.result["mode"], "requirements");
        assert_eq!(outcome.result["result"], "pass");
        // The sentinel ref is used when no real ref is present.
        assert!(
            outcome.result["credentials_ref"]
                .as_str()
                .unwrap()
                .contains("no-material-required"),
            "expected sentinel credentials_ref, got {:?}",
            outcome.result["credentials_ref"]
        );
    }

    /// Fix 1 (Codex C2 #1): the stock default registry
    /// (`EnvPackRegistry::with_builtins()`) must pass requirements for a
    /// `local` env bound to the default `LOCAL_DEPLOYER_PACK` WITHOUT a
    /// `credentials_ref` set. This proves the dead-end circular flow
    /// (requirements → "run bootstrap" → "use requirements instead") is
    /// closed on the operator-facing path.
    #[test]
    fn requirements_default_passes_for_local_deployer_without_credentials_ref() {
        use crate::defaults::LOCAL_DEPLOYER_PACK;

        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs
            .push(make_binding(CapabilitySlot::Deployer, LOCAL_DEPLOYER_PACK));
        // No credentials_ref set — this is the exact operator-facing scenario.
        store.save(&env).unwrap();

        let outcome = requirements_default(
            &store,
            &OpFlags::default(),
            Some(CredentialsRequirementsPayload {
                environment_id: "local".to_string(),
            }),
        )
        .expect("default registry requirements should pass for local-process");
        assert_eq!(outcome.result["result"], "pass");
        let checks = outcome.result["checks"].as_array().unwrap();
        assert_eq!(
            checks.len(),
            2,
            "local-process declares 2 capabilities (fs + port)"
        );
        // Sentinel ref used when no material is needed.
        assert!(
            outcome.result["credentials_ref"]
                .as_str()
                .unwrap()
                .contains("no-material-required"),
            "expected sentinel ref, got {:?}",
            outcome.result["credentials_ref"]
        );
    }

    /// A minimal resolvable deployer so `run_bootstrap`'s A9 resolve passes;
    /// its own credentials are never used — these tests pass an override.
    #[derive(Debug)]
    struct BindResolveHandler;

    impl crate::env_packs::EnvPackHandler for BindResolveHandler {
        fn slot(&self) -> CapabilitySlot {
            CapabilitySlot::Deployer
        }
        fn descriptor_path(&self) -> &str {
            "test.deployer.bind"
        }
        fn supported_versions(&self) -> semver::VersionReq {
            "^0.1.0".parse().unwrap()
        }
        fn deployer_credentials(&self) -> Option<&dyn crate::credentials::DeployerCredentials> {
            // Registration requires a deployer handler to declare credentials;
            // this placeholder is never invoked — `run_bootstrap` is called
            // with an override that replaces it.
            Some(&BindPlaceholderCreds)
        }
    }

    /// Placeholder so `BindResolveHandler` registers; its `bootstrap` is never
    /// reached because the tests pass a `creds_override`.
    #[derive(Debug)]
    struct BindPlaceholderCreds;

    impl crate::credentials::DeployerCredentials for BindPlaceholderCreds {
        fn required_capabilities(&self) -> Vec<crate::credentials::Capability> {
            Vec::new()
        }
        fn validate(
            &self,
            _ctx: &crate::credentials::ValidationContext<'_>,
        ) -> crate::credentials::RequirementsReport {
            crate::credentials::RequirementsReport::new(Vec::new())
        }
        fn bootstrap(
            &self,
            _input: &crate::credentials::BootstrapInput<'_>,
        ) -> Result<crate::credentials::BootstrapOutcome, crate::credentials::BootstrapError>
        {
            Err(crate::credentials::BootstrapError::NotApplicable(
                "placeholder creds are never invoked".to_string(),
            ))
        }
    }

    /// `creds_override` that "mints" a credential: returns material + granted
    /// expiry + the store-aligned bound ref, mirroring the K8s `--bind` path
    /// without a live cluster.
    #[derive(Debug)]
    struct MintingCreds {
        secret_ref: String,
        token: String,
        expiry: chrono::DateTime<chrono::Utc>,
    }

    impl crate::credentials::DeployerCredentials for MintingCreds {
        fn required_capabilities(&self) -> Vec<crate::credentials::Capability> {
            Vec::new()
        }
        fn validate(
            &self,
            _ctx: &crate::credentials::ValidationContext<'_>,
        ) -> crate::credentials::RequirementsReport {
            crate::credentials::RequirementsReport::new(Vec::new())
        }
        fn bootstrap(
            &self,
            _input: &crate::credentials::BootstrapInput<'_>,
        ) -> Result<crate::credentials::BootstrapOutcome, crate::credentials::BootstrapError>
        {
            Ok(crate::credentials::BootstrapOutcome {
                rules_pack: crate::credentials::RulesPack {
                    entries: Vec::new(),
                },
                bound_credentials_ref: Some(SecretRef::try_new(self.secret_ref.clone()).unwrap()),
                bound_expiry: Some(self.expiry),
                bound_secret_material: Some(zeroize::Zeroizing::new(self.token.clone())),
            })
        }
    }

    fn bind_fixture(dir: &std::path::Path) -> (LocalFsStore, EnvPackRegistry, EnvId) {
        let store = LocalFsStore::new(dir);
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "test.deployer.bind@0.1.0",
        ));
        store.save(&env).unwrap();
        let mut registry = EnvPackRegistry::new();
        registry.register(Box::new(BindResolveHandler)).unwrap();
        (store, registry, EnvId::try_from("local").unwrap())
    }

    #[test]
    fn run_bootstrap_writes_material_then_persists_ref_and_expiry() {
        let dir = tempdir().unwrap();
        let (store, registry, env_id) = bind_fixture(dir.path());
        let admin = crate::credentials::ZeroizedAdmin::new("admin-ctx", String::new());
        let expiry = chrono::DateTime::from_timestamp(2_000_000_000, 0).unwrap();
        let bind = MintingCreds {
            secret_ref: "secret://local/default/_/k8s-deployer/deployer_token".to_string(),
            token: "MINTED".to_string(),
            expiry,
        };

        let captured = std::sync::Mutex::new(None);
        let sink =
            |_root: &std::path::Path, secret_ref: &SecretRef, value: &str| -> Result<(), String> {
                *captured.lock().unwrap() =
                    Some((secret_ref.as_str().to_string(), value.to_string()));
                Ok(())
            };

        let doc = crate::credentials::run_bootstrap(
            &store,
            &registry,
            &env_id,
            &admin,
            Some(&bind),
            &sink,
        )
        .expect("bind succeeds");

        // Granted expiry stamped into the doc.
        assert_eq!(doc.expiry.as_ref().map(|e| e.expires_at), Some(expiry));
        // Material written to the sink at the bound ref, BEFORE persisting.
        let (uri, value) = captured.lock().unwrap().clone().expect("sink invoked");
        assert_eq!(uri, "secret://local/default/_/k8s-deployer/deployer_token");
        assert_eq!(value, "MINTED");
        // credentials_ref persisted on the env.
        let reloaded = store.load(&env_id).unwrap();
        assert_eq!(
            reloaded.credentials_ref.as_ref().map(|r| r.as_str()),
            Some("secret://local/default/_/k8s-deployer/deployer_token")
        );
    }

    #[test]
    fn run_bootstrap_aborts_without_persisting_ref_when_the_sink_fails() {
        let dir = tempdir().unwrap();
        let (store, registry, env_id) = bind_fixture(dir.path());
        let admin = crate::credentials::ZeroizedAdmin::new("admin-ctx", String::new());
        let bind = MintingCreds {
            secret_ref: "secret://local/default/_/k8s-deployer/deployer_token".to_string(),
            token: "MINTED".to_string(),
            expiry: chrono::DateTime::from_timestamp(2_000_000_000, 0).unwrap(),
        };
        let sink = |_root: &std::path::Path, _r: &SecretRef, _v: &str| -> Result<(), String> {
            Err("backend unavailable".to_string())
        };

        let err = crate::credentials::run_bootstrap(
            &store,
            &registry,
            &env_id,
            &admin,
            Some(&bind),
            &sink,
        )
        .unwrap_err();
        assert!(
            matches!(err, RunBootstrapError::SecretWrite(_)),
            "got {err:?}"
        );
        // Re-runnable: credentials_ref must NOT persist when the write fails.
        let reloaded = store.load(&env_id).unwrap();
        assert!(
            reloaded.credentials_ref.is_none(),
            "credentials_ref must not persist on sink failure"
        );
    }
}
