//! `op env up` — one-command local K8s environment bootstrap.
//!
//! Orchestrates the full sequence: parse → preflight → cluster → env ensure →
//! apply → reconcile+rollout → access. The staged answers file keeps whatever
//! the manifest declared; the derived `kind-<name>` context is applied only to
//! this reconcile. A later bare `op env reconcile` uses the ambient context —
//! which `kind create cluster` already sets as current-context.

#[cfg(any(feature = "k8s-client", test))]
use serde_json::Value;
use serde_json::json;

use crate::cli::env_manifest::EnvManifest;
use crate::cli::{OpError, OpFlags, OpOutcome, load_answers};
use crate::env_packs::EnvPackRegistry;
use crate::environment::LocalFsStore;

const NOUN: &str = "env";

/// Port-forward descriptor returned by [`up`] when the caller should block
/// on a foreground `kubectl port-forward`.
#[derive(Debug)]
#[allow(dead_code)] // fields read only with `k8s-client`
pub(crate) struct PortForward {
    pub namespace: String,
    pub context: Option<String>,
    pub port: u16,
}

/// CLI arguments for `op env up`.
#[derive(clap::Args, Debug)]
pub struct EnvUpArgs {
    /// Skip the interactive confirmation shown when the plan contains
    /// mutations and stdin/stdout are a TTY.
    #[arg(long)]
    pub yes: bool,
    /// Never prompt for missing inputs — report them instead.
    #[arg(long = "non-interactive")]
    pub non_interactive: bool,
    /// Preview the apply plan without mutating the store or the cluster.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
    /// Skip cluster provisioning (phases 2). Useful when the cluster already
    /// exists and you only want to apply + reconcile.
    #[arg(long = "skip-cluster")]
    pub skip_cluster: bool,
    /// Do not start a foreground port-forward after reconcile.
    #[arg(long = "no-port-forward")]
    pub no_port_forward: bool,
    /// Local port for the router port-forward (default 8080).
    #[arg(long = "port", default_value_t = 8080)]
    pub port: u16,
    /// Downgrade a missing Vault seed (a `vault_bootstrap.seed[]` entry whose
    /// value cannot be resolved and is not already in Vault) from a hard error
    /// to a warning. Off by default: a fresh dev Vault that boots without its
    /// secrets fails only at runtime, so `env up` fails closed instead.
    #[arg(long = "allow-missing-seeds")]
    pub allow_missing_seeds: bool,
    /// Audit principal forwarded to every composed mutation.
    #[arg(long = "updated-by")]
    pub updated_by: Option<String>,
}

/// `op env up` entry point.
///
/// Returns `(OpOutcome, Option<PortForward>)`. The caller prints the outcome
/// **first**, then blocks on the forward — stdout carries exactly one JSON
/// envelope.
pub(crate) fn up(
    store: &LocalFsStore,
    registry: &EnvPackRegistry,
    flags: &OpFlags,
    args: EnvUpArgs,
) -> Result<(OpOutcome, Option<PortForward>), OpError> {
    use crate::cli::env_apply::{ApplyMode, ApplyOptions};
    use crate::environment::EnvironmentStore as _;
    use greentic_deploy_spec::EnvId;

    // ── schema_only ──────────────────────────────────────────────────
    if flags.schema_only {
        return Ok((
            OpOutcome::new(
                NOUN,
                "up",
                json!({
                    "input_schema": "manifest via --answers <PATH>; \
                     --yes, --non-interactive, --dry-run, --skip-cluster, \
                     --no-port-forward, --port <u16>, --allow-missing-seeds, \
                     --updated-by <STRING>"
                }),
            ),
            None,
        ));
    }

    // Fail before any mutation: without `k8s-client` the reconcile phase cannot
    // run, and reaching it after `apply` would leave the store converged against
    // a cluster this build can never talk to.
    if !cfg!(feature = "k8s-client") {
        return Err(OpError::Conflict(
            "this build was compiled without the `k8s-client` feature; \
             `op env up` needs it to reach a cluster"
                .to_string(),
        ));
    }

    // ── Phase 0: parse ───────────────────────────────────────────────
    let answers_path = flags.answers.as_ref().ok_or_else(|| {
        OpError::InvalidArgument(
            "`op env up` requires --answers <PATH> pointing to a \
                 greentic.env-manifest.v1 document"
                .to_string(),
        )
    })?;
    let manifest: EnvManifest = load_answers(answers_path)?;
    manifest.validate_shape()?;

    let env_id_str = &manifest.environment.id;
    let env_id = EnvId::try_from(env_id_str.as_str())
        .map_err(|e| OpError::InvalidArgument(format!("environment.id: {e}")))?;

    let has_cluster = manifest.cluster.is_some();
    let provision_cluster = should_provision_cluster(has_cluster, args.skip_cluster, args.dry_run);

    // ── Phase 1: preflight ───────────────────────────────────────────
    if has_cluster && !args.skip_cluster {
        let kind_check = crate::tool_check::kind();
        if !kind_check.outcome.is_ok() {
            return Err(OpError::InvalidArgument(format!(
                "preflight: kind: {}",
                preflight_detail(&kind_check.outcome)
            )));
        }
        let docker_check = crate::tool_check::docker();
        if !docker_check.outcome.is_ok() {
            return Err(OpError::InvalidArgument(format!(
                "preflight: docker: {}",
                preflight_detail(&docker_check.outcome)
            )));
        }
    }
    if !args.no_port_forward && has_cluster {
        let kubectl_check = crate::tool_check::kubectl();
        if !kubectl_check.outcome.is_ok() {
            return Err(OpError::InvalidArgument(format!(
                "preflight: kubectl: {}",
                preflight_detail(&kubectl_check.outcome)
            )));
        }
    }

    // ── Phase 2: cluster ─────────────────────────────────────────────
    // When we do not provision, the context is still derived from the manifest
    // rather than left to the ambient kubeconfig: a declared `cluster` names the
    // target, and `--skip-cluster` only means "it already exists".
    let ctx: Option<String> = if provision_cluster {
        ensure_kind_cluster(&manifest)?
    } else {
        if args.dry_run && has_cluster && !args.skip_cluster {
            let cluster = manifest.cluster.as_ref().expect("has_cluster");
            eprintln!(
                "[env up] dry-run: would ensure kind cluster `{}` and load {} image(s)",
                cluster.name,
                cluster.load_images.len()
            );
        }
        manifest.cluster.as_ref().map(|c| {
            c.kubeconfig_context
                .clone()
                .unwrap_or_else(|| kind_context_name(&c.name))
        })
    };

    // ── Phase 3: env ensure ──────────────────────────────────────────
    if env_id_str != "local" && !store.exists(&env_id)? {
        let tenant_org_id = manifest.environment.tenant_org_id.clone();
        // Require tenant_org_id for non-local envs so the runtime doesn't
        // start with a null org context.
        if tenant_org_id.is_none() {
            return Err(OpError::InvalidArgument(format!(
                "environment `{env_id}` does not exist and `environment.tenant_org_id` \
                 is not set in the manifest; set it so `env up` can create the environment. \
                 Re-running `op env up` is safe"
            )));
        }
        // `env_apply::apply` refuses to plan against an environment that does not
        // exist, so a dry run cannot go further than naming what it would create.
        if args.dry_run {
            eprintln!("[env up] dry-run: would create environment `{env_id}`");
            return Ok((
                OpOutcome::new(
                    NOUN,
                    "up",
                    json!({
                        "dry_run": true,
                        "environment_id": env_id_str,
                        "environment_exists": false,
                        "note": "environment would be created; the apply plan cannot be \
                                 computed until it exists",
                    }),
                ),
                None,
            ));
        }
        eprintln!("[env up] creating environment `{env_id}`");
        super::env::create(
            store,
            flags,
            Some(crate::cli::env::EnvCreatePayload {
                environment_id: env_id_str.clone(),
                name: manifest
                    .environment
                    .name
                    .clone()
                    .unwrap_or_else(|| env_id_str.clone()),
                region: manifest.environment.region.clone(),
                tenant_org_id,
                listen_addr: manifest.environment.listen_addr.clone(),
                public_base_url: manifest.environment.public_base_url.clone(),
            }),
        )?;
    }

    // ── Phase 4: apply ───────────────────────────────────────────────
    let mode = if args.dry_run {
        ApplyMode::DryRun
    } else {
        ApplyMode::Apply
    };
    let apply_outcome = super::env_apply::apply(
        store,
        flags,
        ApplyOptions {
            mode,
            updated_by: args.updated_by.clone(),
            yes: args.yes,
            non_interactive: args.non_interactive,
            ..Default::default()
        },
    )?;

    if args.dry_run {
        return Ok((apply_outcome, None));
    }

    // ── Phase 4b: vault ──────────────────────────────────────────────
    // Deploy + bootstrap + seed an in-cluster (or external) Vault, when the
    // manifest declares one. Pinned AFTER apply (the secrets binding it needs
    // is now in the store) and BEFORE reconcile (workers boot there and must
    // find their secrets already present).
    let vault_report = if manifest.vault_bootstrap.is_some() {
        Some(vault_phase(
            store,
            &env_id,
            &manifest,
            ctx.as_deref(),
            args.non_interactive,
            args.allow_missing_seeds,
        )?)
    } else {
        None
    };

    // ── Phase 5: reconcile + rollout ─────────────────────────────────
    let (report, namespace) = reconcile_phase(store, registry, &env_id, ctx.as_deref())?;

    // ── Phase 6b: verify ─────────────────────────────────────────────
    // Vault only: confirm the reconciled worker is Vault-shaped (SA `gtc-worker`,
    // `VAULT_*` env) — a belt-and-suspenders check that the secrets backend
    // resolved as Vault end to end.
    if let Some(vault) = &vault_report {
        vault_verify_phase(&vault.worker_namespace, ctx.as_deref())?;
    }

    // ── Phase 6: access ──────────────────────────────────────────────
    eprintln!(
        "[env up] reconciled: {} applied, {} pruned",
        report.applied.len(),
        report.pruned.len()
    );
    eprintln!("[env up] namespace: {namespace}");
    eprintln!("[env up] router service: gtc-router");
    eprintln!();
    eprintln!("[env up] teardown:");
    if let Some(cluster) = &manifest.cluster {
        eprintln!("  kind delete cluster --name {}", cluster.name);
    }
    eprintln!("  store root: {}", store.root().display());

    let forward = if args.no_port_forward {
        None
    } else {
        Some(PortForward {
            namespace,
            context: ctx,
            port: args.port,
        })
    };

    let mut result = json!({
        "environment_id": env_id.as_str(),
        "applied_count": report.applied.len(),
        "pruned_count": report.pruned.len(),
        "applied": report.applied,
        "pruned": report.pruned,
    });
    if let Some(vault) = &vault_report {
        result["vault"] = json!({
            "namespace": vault.namespace,
            "deploy": if vault.dev_in_cluster { "dev-in-cluster" } else { "external" },
            "was_already_configured": vault.was_already_configured,
            "seeded": vault.seeds.seeded,
            "skipped_present": vault.seeds.skipped_present,
            "warned_missing": vault.seeds.warned_missing,
        });
    }

    Ok((OpOutcome::new(NOUN, "up", result), forward))
}

/// Phase 5 — reconcile + rollout, gated on `k8s-client`.
#[cfg(feature = "k8s-client")]
fn reconcile_phase(
    store: &LocalFsStore,
    registry: &EnvPackRegistry,
    env_id: &greentic_deploy_spec::EnvId,
    ctx: Option<&str>,
) -> Result<(crate::env_packs::k8s::ReconcileReport, String), OpError> {
    use crate::environment::EnvironmentStore as _;
    use greentic_deploy_spec::CapabilitySlot;

    let env = store.load(env_id)?;
    let descriptor = super::env::resolve_live_deployer_kind(&env, None)?;

    let k8s_path = crate::env_packs::k8s::K8sDeployerHandler::DESCRIPTOR_PATH;
    if descriptor.path() != k8s_path {
        return Err(OpError::Conflict(format!(
            "`op env up` is only supported for the `{k8s_path}` deployer env-pack \
             today; `{}` cannot be reconciled to a live cluster",
            descriptor.path()
        )));
    }

    // Parity with reconcile: confirm the kind is actually registered.
    let _handler = registry
        .resolve_for_slot(CapabilitySlot::Deployer, &descriptor)
        .map_err(|e| OpError::Conflict(e.to_string()))?;

    let (answers, _wire) = super::env::load_render_answers(store, &env, &descriptor)?;
    let answers = merge_kubeconfig_context(answers, ctx)?;

    let bound_token =
        crate::env_packs::k8s::resolve_bound_identity(store, &env, env_id, answers.as_ref())?;
    let dev_secrets = super::env::read_dev_secrets_b64(store, env_id)?;
    let secrets_backend = super::env::resolve_secrets_backend(store, &env)?;

    let report = super::env::reconcile_k8s_cluster(
        &env,
        answers.as_ref(),
        bound_token,
        dev_secrets,
        secrets_backend,
        true,
    )?;

    // Derive the namespace from the answers (same logic the renderer uses):
    // explicit answer wins, otherwise `gtc-<env_id>`.
    let namespace = answers
        .as_ref()
        .and_then(|a| a.get("namespace"))
        .and_then(Value::as_str)
        .map(String::from)
        .unwrap_or_else(|| crate::env_packs::k8s::manifests::namespace_for_env(env_id));

    Ok((report, namespace))
}

#[cfg(not(feature = "k8s-client"))]
fn reconcile_phase(
    _store: &LocalFsStore,
    _registry: &EnvPackRegistry,
    _env_id: &greentic_deploy_spec::EnvId,
    _ctx: Option<&str>,
) -> Result<(crate::env_packs::k8s::ReconcileReport, String), OpError> {
    Err(OpError::Conflict(
        "this build was compiled without the `k8s-client` feature; \
         `op env up` needs it to connect to a cluster"
            .to_string(),
    ))
}

// ── Phase 4b/6b: Vault ───────────────────────────────────────────────

/// The dev Vault's in-cluster HTTP port.
#[cfg(feature = "k8s-client")]
const VAULT_REMOTE_PORT: u16 = 8200;
/// The API server URL Vault's Kubernetes auth reviews worker tokens against.
#[cfg(feature = "k8s-client")]
const VAULT_KUBERNETES_HOST: &str = "https://kubernetes.default.svc";
/// The cluster-scoped verb the in-cluster Vault path needs (its
/// `system:auth-delegator` ClusterRoleBinding). Preflighted before apply.
#[cfg(feature = "k8s-client")]
const VAULT_CRB_CREATE_OP: crate::env_packs::k8s::credentials::K8sOperation =
    crate::env_packs::k8s::credentials::K8sOperation {
        group: "rbac.authorization.k8s.io",
        resource: "clusterrolebindings",
        verb: "create",
    };

/// What the seed phase did, threaded into the `up` outcome.
#[derive(Debug, Default, Clone)]
struct SeedSummary {
    seeded: usize,
    skipped_present: usize,
    warned_missing: usize,
}

/// The vault phase result, for the outcome + verify.
#[derive(Debug, Clone)]
struct VaultPhaseReport {
    namespace: String,
    worker_namespace: String,
    dev_in_cluster: bool,
    was_already_configured: bool,
    seeds: SeedSummary,
}

/// The action to take for a seed whose value could not be resolved. Pure
/// decision table (unit-tested): a present secret on a surviving Vault is a
/// skip; otherwise a missing value is a hard error unless `--allow-missing-seeds`
/// downgrades it to a warning. (A fresh Vault always passes `present=false`.)
#[cfg(any(feature = "k8s-client", test))]
#[derive(Debug, PartialEq, Eq)]
enum MissingSeedAction {
    SkipPresent,
    Warn,
    Fail,
}

#[cfg(any(feature = "k8s-client", test))]
fn decide_missing_seed(present_in_vault: bool, allow_missing: bool) -> MissingSeedAction {
    if present_in_vault {
        MissingSeedAction::SkipPresent
    } else if allow_missing {
        MissingSeedAction::Warn
    } else {
        MissingSeedAction::Fail
    }
}

/// Fail closed unless every cluster-scoped preflight decision is `Allowed`.
/// On denial, name `vault_bootstrap.deploy: "external"` as the path for a
/// cluster where the operator lacks cluster-admin RBAC.
#[cfg(any(feature = "k8s-client", test))]
fn evaluate_cluster_crb_preflight(
    decisions: &[crate::env_packs::k8s::credentials::OperationDecision],
) -> Result<(), OpError> {
    use crate::env_packs::k8s::credentials::AccessDecision;
    for d in decisions {
        if let AccessDecision::Denied(reason) = &d.decision {
            return Err(OpError::Conflict(format!(
                "in-cluster Vault (`vault_bootstrap.deploy: \"dev-in-cluster\"`) needs a \
                 cluster-admin kubeconfig: the current credential cannot `create` \
                 `clusterrolebindings` ({reason}). Use an admin context (kind / local dev), or \
                 set `vault_bootstrap.deploy: \"external\"` and point the binding at a Vault you \
                 provisioned separately"
            )));
        }
    }
    Ok(())
}

/// A transient `kubectl port-forward` to the dev Vault, killed on drop. stdout
/// and stderr are silenced; `start` polls the local port until it accepts (or
/// the child dies) before returning, so callers can dial it immediately.
#[cfg(feature = "k8s-client")]
struct VaultPortForward {
    child: std::process::Child,
    local_port: u16,
}

#[cfg(feature = "k8s-client")]
impl VaultPortForward {
    fn start(context: Option<&str>, namespace: &str, remote_port: u16) -> Result<Self, OpError> {
        use std::process::{Command, Stdio};
        // Reserve an ephemeral local port, then release it for kubectl to bind.
        // A tiny TOCTOU race window remains (another process could grab it); the
        // readiness poll below surfaces that as a clear failure.
        let local_port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| {
                OpError::Conflict(format!("vault: could not reserve a local port: {e}"))
            })?;
            l.local_addr()
                .map_err(|e| OpError::Conflict(format!("vault: local port: {e}")))?
                .port()
        };
        let mut cmd = Command::new("kubectl");
        if let Some(ctx) = context {
            cmd.args(["--context", ctx]);
        }
        cmd.args([
            "-n",
            namespace,
            "port-forward",
            "svc/vault",
            &format!("{local_port}:{remote_port}"),
        ]);
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
        let child = cmd.spawn().map_err(|e| {
            OpError::Conflict(format!(
                "vault: failed to spawn `kubectl port-forward`: {e}"
            ))
        })?;
        let mut pf = Self { child, local_port };
        pf.wait_ready()?;
        Ok(pf)
    }

    fn wait_ready(&mut self) -> Result<(), OpError> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                return Err(OpError::Conflict(format!(
                    "vault: `kubectl port-forward` exited early ({status}); is `svc/vault` up in \
                     this namespace and the context an admin kubeconfig?"
                )));
            }
            if std::net::TcpStream::connect(("127.0.0.1", self.local_port)).is_ok() {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(OpError::Conflict(
                    "vault: `kubectl port-forward` did not become ready within 20s".to_string(),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    fn addr(&self) -> String {
        format!("http://127.0.0.1:{}", self.local_port)
    }
}

#[cfg(feature = "k8s-client")]
impl Drop for VaultPortForward {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Block until the dev Vault Deployment has rolled out (availability is gated by
/// its `/v1/sys/health` readiness probe, so this also means Vault answers HTTP).
#[cfg(feature = "k8s-client")]
async fn wait_for_vault_rollout(
    cluster: &dyn crate::env_packs::k8s::K8sCluster,
    deployment: &crate::env_packs::k8s::ObjectRef,
) -> Result<(), OpError> {
    let timeout = std::time::Duration::from_secs(180);
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let status = cluster
            .get_rollout_status(deployment)
            .await
            .map_err(|e| OpError::Conflict(format!("vault: rollout status: {e}")))?;
        if status.is_complete(1) {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(OpError::Conflict(format!(
                "vault: deployment `{deployment}` did not become ready within {}s",
                timeout.as_secs()
            )));
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

/// Resolve the namespace the worker pods run in (the answers' `namespace`, else
/// the env-derived default) — where the Vault role binds the worker SA and where
/// verify lists the worker Deployment.
#[cfg(feature = "k8s-client")]
fn resolve_worker_namespace(
    store: &LocalFsStore,
    env: &greentic_deploy_spec::Environment,
    env_id: &greentic_deploy_spec::EnvId,
) -> Result<String, OpError> {
    let descriptor = super::env::resolve_live_deployer_kind(env, None)?;
    let (answers, _wire) = super::env::load_render_answers(store, env, &descriptor)?;
    Ok(answers
        .as_ref()
        .and_then(|a| a.get("namespace"))
        .and_then(Value::as_str)
        .map(String::from)
        .unwrap_or_else(|| crate::env_packs::k8s::manifests::namespace_for_env(env_id)))
}

/// Build the native bootstrap params from the env's Vault binding + the
/// reachable address and worker identity.
#[cfg(feature = "k8s-client")]
#[allow(clippy::too_many_arguments)]
fn vault_bootstrap_params<'a>(
    addr: &'a str,
    token: &'a str,
    binding: &'a crate::env_packs::k8s::manifests::VaultBackend,
    env_id: &'a str,
    tenant: &'a str,
    worker_sa: &'a str,
    worker_namespace: &'a str,
) -> crate::env_packs::k8s::vault_bootstrap::VaultBootstrapParams<'a> {
    crate::env_packs::k8s::vault_bootstrap::VaultBootstrapParams {
        addr,
        token,
        kv_mount: &binding.kv_mount,
        kv_prefix: &binding.kv_prefix,
        transit_mount: &binding.transit_mount,
        transit_key: &binding.transit_key,
        auth_mount: &binding.auth_mount,
        env_id,
        tenant,
        worker_sa,
        worker_namespace,
        role: &binding.k8s_role,
        kubernetes_host: VAULT_KUBERNETES_HOST,
    }
}

/// A teachable hard-error message for a missing seed value.
#[cfg(feature = "k8s-client")]
fn missing_seed_message(
    rel_path: &str,
    seed: &crate::cli::env_manifest::ManifestSecret,
    was_configured: bool,
) -> String {
    let source = match &seed.from_env {
        Some(var) => format!("environment variable `${var}` is unset or empty"),
        None => "no value was provided (empty paste or --non-interactive)".to_string(),
    };
    let vault_state = if was_configured {
        "and it is not already present in Vault"
    } else {
        "and the freshly-bootstrapped Vault cannot already hold it"
    };
    format!(
        "vault seed `{rel_path}`: {source}, {vault_state}. Export the value, supply a masked \
         paste, or pass --allow-missing-seeds to downgrade this to a warning"
    )
}

/// Seed every `vault_bootstrap.seed[]` entry into Vault over `addr` (an explicit
/// port-forward or external address), scoped to `tenant`. A resolvable value is
/// always written (idempotent); a missing value follows the
/// [`decide_missing_seed`] matrix.
#[cfg(feature = "k8s-client")]
#[allow(clippy::too_many_arguments)]
fn seed_secrets(
    binding: &crate::env_packs::k8s::manifests::VaultBackend,
    addr: &str,
    token: &str,
    tenant: &str,
    env_id: &greentic_deploy_spec::EnvId,
    seeds: &[crate::cli::env_manifest::ManifestSecret],
    was_already_configured: bool,
    allow_missing_seeds: bool,
    non_interactive: bool,
) -> Result<SeedSummary, OpError> {
    use greentic_secrets_lib::vault::VaultAuth;
    let mut summary = SeedSummary::default();
    for seed in seeds {
        let rel_path = seed.path.trim_start_matches('/');
        let store_uri = format!("secrets://{}/{rel_path}", env_id.as_str());
        let value = match &seed.from_env {
            Some(var) => std::env::var(var).ok().filter(|v| !v.is_empty()),
            None if !non_interactive => rpassword::prompt_password(format!(
                "seed `{rel_path}`: enter value (hidden; empty to skip): "
            ))
            .ok()
            .filter(|v| !v.is_empty()),
            None => None,
        };
        let cfg = || {
            super::secrets::vault_backend_config_from_binding(
                binding,
                addr.to_string(),
                VaultAuth::Token(token.to_string()),
            )
        };
        match value {
            Some(v) => {
                super::secrets::vault_put_with_config(cfg(), tenant, &store_uri, &v)?;
                eprintln!("[env up] vault: seeded `{rel_path}`");
                summary.seeded += 1;
            }
            None => {
                let present = was_already_configured
                    && super::secrets::vault_get_with_config(cfg(), tenant, &store_uri)?.is_some();
                match decide_missing_seed(present, allow_missing_seeds) {
                    MissingSeedAction::SkipPresent => {
                        eprintln!(
                            "[env up] vault: `{rel_path}` already present in Vault, skipping"
                        );
                        summary.skipped_present += 1;
                    }
                    MissingSeedAction::Warn => {
                        eprintln!(
                            "[env up] vault: WARNING `{rel_path}` has no value and is not in \
                             Vault (--allow-missing-seeds)"
                        );
                        summary.warned_missing += 1;
                    }
                    MissingSeedAction::Fail => {
                        return Err(OpError::InvalidArgument(missing_seed_message(
                            rel_path,
                            seed,
                            was_already_configured,
                        )));
                    }
                }
            }
        }
    }
    Ok(summary)
}

/// Phase 4b — deploy (dev-in-cluster), bootstrap, and seed the env's Vault.
/// Runs after apply (the secrets binding is in the store) and before reconcile
/// (workers boot there and must find their secrets present).
#[cfg(feature = "k8s-client")]
fn vault_phase(
    store: &LocalFsStore,
    env_id: &greentic_deploy_spec::EnvId,
    manifest: &EnvManifest,
    ctx: Option<&str>,
    non_interactive: bool,
    allow_missing_seeds: bool,
) -> Result<VaultPhaseReport, OpError> {
    use crate::env_packs::k8s::async_bridge::run_k8s_async;
    use crate::env_packs::k8s::credentials::K8sValidatorClient as _;
    use crate::env_packs::k8s::kube_client::connect;
    use crate::env_packs::k8s::manifests::{SecretsBackend, WORKER_SERVICE_ACCOUNT};
    use crate::env_packs::k8s::vault_infra::{
        VaultInfraParams, render_vault_deployment, render_vault_manifests,
    };
    use crate::env_packs::k8s::{K8sCluster as _, KubeCluster, KubeValidatorClient, ObjectRef};
    use crate::environment::EnvironmentStore as _;

    let vault_cfg = manifest
        .vault_bootstrap
        .as_ref()
        .expect("caller checks vault_bootstrap.is_some()");
    let env = store.load(env_id)?;

    let SecretsBackend::Vault(binding) = super::env::resolve_secrets_backend(store, &env)? else {
        return Err(OpError::InvalidArgument(
            "manifest declares `vault_bootstrap` but the env's secrets binding is not \
             Vault-backed; bind a `greentic.secrets.vault@*` pack in packs[] so the worker \
             resolves `secret://` refs against Vault"
                .to_string(),
        ));
    };

    let tenant = env
        .host_config
        .tenant_org_id
        .clone()
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| {
            OpError::InvalidArgument(
                "a Vault-backed env must be tenant-owned before seeding; set \
                 `environment.tenant_org_id` in the manifest"
                    .to_string(),
            )
        })?;

    let vault_ns = vault_cfg.resolved_namespace().to_string();
    let worker_ns = resolve_worker_namespace(store, &env, env_id)?;
    let dev_in_cluster = vault_cfg.is_dev_in_cluster();

    // 4b.1 — deploy + rollout (dev-in-cluster only): SSAR preflight, apply the
    // Vault objects, wait for the pod, all in ONE bridge call (the kube client's
    // buffer worker lives on that runtime).
    if dev_in_cluster {
        let params = VaultInfraParams {
            namespace: &vault_ns,
            image: vault_cfg.resolved_image(),
            root_token: vault_cfg.resolved_root_token(),
            env_id: env_id.as_str(),
        };
        let objects = render_vault_manifests(&params);
        let deploy_ref = ObjectRef::from_manifest(&render_vault_deployment(&params))
            .map_err(|e| OpError::Conflict(format!("vault: deployment ref: {e}")))?;
        let ctx_owned = ctx.map(str::to_string);
        run_k8s_async(async move {
            let client = connect(ctx_owned.as_deref(), None)
                .await
                .map_err(|e| OpError::Conflict(format!("vault: connect: {e}")))?;
            let validator = KubeValidatorClient::new(client.clone());
            let decisions = validator
                .review_cluster_access(&[VAULT_CRB_CREATE_OP])
                .await
                .map_err(|e| OpError::Conflict(format!("vault: cluster access review: {e}")))?;
            evaluate_cluster_crb_preflight(&decisions)?;
            let cluster = KubeCluster::new(client.clone());
            for obj in &objects {
                cluster.apply(obj).await.map_err(|e| {
                    OpError::Conflict(format!(
                        "vault: apply {}: {e}",
                        obj.get("kind").and_then(Value::as_str).unwrap_or("object")
                    ))
                })?;
            }
            wait_for_vault_rollout(&cluster, &deploy_ref).await?;
            Ok::<(), OpError>(())
        })?;
        eprintln!("[env up] vault: deployed + ready in namespace `{vault_ns}`");
    }

    // 4b.2 — bootstrap + seed. dev-in-cluster reaches Vault over a transient
    // port-forward; external seeds directly against the binding address. Both
    // run OUTSIDE the async bridge (blocking reqwest + blocking seed core).
    let root_token = vault_cfg.resolved_root_token();
    let (was_already_configured, seeds) = if dev_in_cluster {
        let pf = VaultPortForward::start(ctx, &vault_ns, VAULT_REMOTE_PORT)?;
        let addr = pf.addr();
        let outcome = crate::env_packs::k8s::vault_bootstrap::bootstrap(&vault_bootstrap_params(
            &addr,
            root_token,
            &binding,
            env_id.as_str(),
            &tenant,
            WORKER_SERVICE_ACCOUNT,
            &worker_ns,
        ))
        .map_err(|e| OpError::Conflict(format!("vault bootstrap: {e}")))?;
        eprintln!(
            "[env up] vault: bootstrapped ({})",
            if outcome.was_already_configured {
                "already configured"
            } else {
                "fresh"
            }
        );
        let seeds = seed_secrets(
            &binding,
            &addr,
            root_token,
            &tenant,
            env_id,
            &vault_cfg.seed,
            outcome.was_already_configured,
            allow_missing_seeds,
            non_interactive,
        )?;
        drop(pf); // kill the port-forward
        (outcome.was_already_configured, seeds)
    } else {
        eprintln!(
            "[env up] vault: external mode — skipping deploy + bootstrap, seeding against `{}`",
            binding.addr
        );
        let seeds = seed_secrets(
            &binding,
            &binding.addr,
            root_token,
            &tenant,
            env_id,
            &vault_cfg.seed,
            true, // a surviving external Vault: existence-checked seed semantics
            allow_missing_seeds,
            non_interactive,
        )?;
        (true, seeds)
    };

    Ok(VaultPhaseReport {
        namespace: vault_ns,
        worker_namespace: worker_ns,
        dev_in_cluster,
        was_already_configured,
        seeds,
    })
}

#[cfg(not(feature = "k8s-client"))]
fn vault_phase(
    _store: &LocalFsStore,
    _env_id: &greentic_deploy_spec::EnvId,
    _manifest: &EnvManifest,
    _ctx: Option<&str>,
    _non_interactive: bool,
    _allow_missing_seeds: bool,
) -> Result<VaultPhaseReport, OpError> {
    Err(OpError::Conflict(
        "this build was compiled without the `k8s-client` feature; \
         `op env up` needs it to provision Vault"
            .to_string(),
    ))
}

/// Phase 6b — verify (vault only): after reconcile, confirm at least one worker
/// Deployment in the worker namespace is Vault-shaped (SA `gtc-worker`, a
/// `VAULT_*` env var). A belt-and-suspenders check that the secrets backend
/// resolved as Vault end to end.
#[cfg(feature = "k8s-client")]
fn vault_verify_phase(worker_namespace: &str, ctx: Option<&str>) -> Result<(), OpError> {
    use crate::env_packs::k8s::async_bridge::run_k8s_async;
    use crate::env_packs::k8s::kube_client::connect;
    use crate::env_packs::k8s::manifests::WORKER_SERVICE_ACCOUNT;
    use k8s_openapi::api::apps::v1::Deployment;
    use kube::Api;
    use kube::api::ListParams;

    let ns = worker_namespace.to_string();
    let ctx_owned = ctx.map(str::to_string);
    run_k8s_async(async move {
        let client = connect(ctx_owned.as_deref(), None)
            .await
            .map_err(|e| OpError::Conflict(format!("vault verify: connect: {e}")))?;
        let api: Api<Deployment> = Api::namespaced(client, &ns);
        let list = api
            .list(&ListParams::default().labels("app.kubernetes.io/component=worker"))
            .await
            .map_err(|e| OpError::Conflict(format!("vault verify: list workers: {e}")))?;
        if list.items.is_empty() {
            return Err(OpError::Conflict(format!(
                "vault verify: no worker Deployment found in `{ns}` to verify"
            )));
        }
        for dep in &list.items {
            let name = dep.metadata.name.clone().unwrap_or_default();
            let pod_spec = dep.spec.as_ref().and_then(|s| s.template.spec.as_ref());
            let sa = pod_spec.and_then(|p| p.service_account_name.as_deref());
            if sa != Some(WORKER_SERVICE_ACCOUNT) {
                return Err(OpError::Conflict(format!(
                    "vault verify: worker `{name}` runs as `{}`, expected `{WORKER_SERVICE_ACCOUNT}` \
                     — the secrets backend did not resolve as Vault",
                    sa.unwrap_or("<none>")
                )));
            }
            let has_vault_env = pod_spec
                .map(|p| {
                    p.containers.iter().any(|c| {
                        c.env.as_ref().is_some_and(|env| {
                            env.iter()
                                .any(|e| e.name == "VAULT_ADDR" || e.name == "VAULT_K8S_ROLE")
                        })
                    })
                })
                .unwrap_or(false);
            if !has_vault_env {
                return Err(OpError::Conflict(format!(
                    "vault verify: worker `{name}` carries no `VAULT_*` env — not Vault-shaped"
                )));
            }
        }
        eprintln!("[env up] vault: verified worker is Vault-shaped");
        Ok::<(), OpError>(())
    })
}

#[cfg(not(feature = "k8s-client"))]
fn vault_verify_phase(_worker_namespace: &str, _ctx: Option<&str>) -> Result<(), OpError> {
    Err(OpError::Conflict(
        "this build was compiled without the `k8s-client` feature".to_string(),
    ))
}

/// Block on a foreground `kubectl port-forward`. The child's stdout is
/// silenced (`Stdio::null`); our "Forwarding..." line goes to stderr.
/// A Ctrl-C (SIGINT) reaches both the child and us — treat exit 130 /
/// killed as success.
#[cfg(feature = "k8s-client")]
pub(crate) fn run_port_forward(pf: &PortForward) -> Result<(), OpError> {
    run_port_forward_with_runner(pf, &crate::desktop::RealCommandRunner)
}

/// Port-forward against an injected runner, so tests can drive every exit path
/// without a cluster. See [`run_port_forward`] for the semantics.
#[cfg(any(feature = "k8s-client", test))]
fn run_port_forward_with_runner(
    pf: &PortForward,
    runner: &dyn crate::desktop::CommandRunner,
) -> Result<(), OpError> {
    use std::process::{Command, Stdio};

    let mut cmd = Command::new("kubectl");
    if let Some(ctx) = &pf.context {
        cmd.args(["--context", ctx]);
    }
    cmd.args([
        "-n",
        &pf.namespace,
        "port-forward",
        "svc/gtc-router",
        &format!("{}:8080", pf.port),
    ]);
    cmd.stdout(Stdio::null());
    // stderr inherited — kubectl's own output goes to the terminal.

    eprintln!(
        "[env up] forwarding http://localhost:{} -> svc/gtc-router:8080 (Ctrl-C to stop)",
        pf.port
    );

    // `{e:#}` so the runner's context and the underlying io error both survive.
    let status = runner.run(&mut cmd).map_err(|e| {
        OpError::Conflict(format!(
            "failed to spawn `kubectl port-forward`: {e:#}. \
             Re-running `op env up` is safe"
        ))
    })?;

    // 130 = SIGINT (Ctrl-C), which is the normal exit path.
    if status.success() || status.code() == Some(130) {
        return Ok(());
    }
    // On Unix a killed-by-signal child has no exit code.
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if status.signal().is_some() {
            return Ok(());
        }
    }
    Err(OpError::Conflict(format!(
        "`kubectl port-forward` exited with {status}. \
         Re-running `op env up` is safe"
    )))
}

#[cfg(not(feature = "k8s-client"))]
pub(crate) fn run_port_forward(_pf: &PortForward) -> Result<(), OpError> {
    Err(OpError::Conflict(
        "this build was compiled without the `k8s-client` feature; \
         `op env up` needs it to run port-forward"
            .to_string(),
    ))
}

// ── Phase 2 helpers ──────────────────────────────────────────────────

/// Provision a kind cluster and return the resolved kubeconfig context.
#[cfg(feature = "k8s-client")]
fn ensure_kind_cluster(manifest: &EnvManifest) -> Result<Option<String>, OpError> {
    ensure_kind_cluster_with_runner(manifest, &crate::desktop::RealCommandRunner)
}

/// Provision a kind cluster against an injected runner, so tests can drive the
/// `kind` / `docker` sequence without either binary installed.
#[cfg(any(feature = "k8s-client", test))]
fn ensure_kind_cluster_with_runner(
    manifest: &EnvManifest,
    runner: &dyn crate::desktop::CommandRunner,
) -> Result<Option<String>, OpError> {
    use std::process::Command;

    let cluster = manifest
        .cluster
        .as_ref()
        .expect("caller checks cluster.is_some()");
    let name = &cluster.name;

    // Check whether the cluster already exists.
    // `{e:#}` so the runner's context and the underlying io error both survive.
    let mut list_cmd = Command::new("kind");
    list_cmd.args(["get", "clusters"]);
    let list_output = runner.output(&mut list_cmd).map_err(|e| {
        OpError::Conflict(format!(
            "phase 2 (cluster): failed to run `kind get clusters`: {e:#}. \
             Re-running `op env up` is safe"
        ))
    })?;
    // A failed listing yields empty stdout, which would otherwise read as "no such
    // cluster" and blame the create that follows. The usual cause is a stopped
    // Docker daemon, which the binary-presence preflight cannot detect.
    if !list_output.status.success() {
        return Err(OpError::Conflict(format!(
            "phase 2 (cluster): `kind get clusters` exited with {}: {}. \
             Is the Docker daemon running? Re-running `op env up` is safe",
            list_output.status,
            String::from_utf8_lossy(&list_output.stderr).trim()
        )));
    }
    let list_stdout = String::from_utf8_lossy(&list_output.stdout);

    if !kind_cluster_exists(&list_stdout, name) {
        eprintln!("[env up] creating kind cluster `{name}`");
        let mut create_cmd = Command::new("kind");
        create_cmd.args(["create", "cluster", "--name", name]);
        let status = runner.run(&mut create_cmd).map_err(|e| {
            OpError::Conflict(format!(
                "phase 2 (cluster): failed to run `kind create cluster`: {e:#}. \
                 Re-running `op env up` is safe"
            ))
        })?;
        if !status.success() {
            return Err(OpError::Conflict(format!(
                "phase 2 (cluster): `kind create cluster --name {name}` exited with {status}. \
                 Re-running `op env up` is safe"
            )));
        }
    } else {
        eprintln!("[env up] kind cluster `{name}` already exists");
    }

    // Load images.
    for img in &cluster.load_images {
        eprintln!("[env up] pulling image `{img}`");
        let mut pull_cmd = Command::new("docker");
        pull_cmd.args(["pull", img]);
        let status = runner.run(&mut pull_cmd).map_err(|e| {
            OpError::Conflict(format!(
                "phase 2 (cluster): `docker pull {img}` failed: {e:#}. \
                 Re-running `op env up` is safe"
            ))
        })?;
        if !status.success() {
            return Err(OpError::Conflict(format!(
                "phase 2 (cluster): `docker pull {img}` exited with {status}. \
                 Re-running `op env up` is safe"
            )));
        }

        eprintln!("[env up] loading image `{img}` into kind cluster `{name}`");
        let mut load_cmd = Command::new("kind");
        load_cmd.args(["load", "docker-image", img, "--name", name]);
        let status = runner.run(&mut load_cmd).map_err(|e| {
            OpError::Conflict(format!(
                "phase 2 (cluster): `kind load docker-image {img}` failed: {e:#}. \
                 Re-running `op env up` is safe"
            ))
        })?;
        if !status.success() {
            return Err(OpError::Conflict(format!(
                "phase 2 (cluster): `kind load docker-image {img} --name {name}` exited with {status}. \
                 Re-running `op env up` is safe"
            )));
        }
    }

    let ctx = cluster
        .kubeconfig_context
        .clone()
        .unwrap_or_else(|| kind_context_name(name));

    Ok(Some(ctx))
}

#[cfg(not(feature = "k8s-client"))]
fn ensure_kind_cluster(_manifest: &EnvManifest) -> Result<Option<String>, OpError> {
    Err(OpError::Conflict(
        "this build was compiled without the `k8s-client` feature; \
         `op env up` needs it to manage the kind cluster"
            .to_string(),
    ))
}

// ── Pure helpers (unit-tested) ───────────────────────────────────────

/// Check whether `kind get clusters` stdout lists a cluster with the given name.
/// Exact line match, trims whitespace.
#[cfg(any(feature = "k8s-client", test))]
fn kind_cluster_exists(list_stdout: &str, name: &str) -> bool {
    list_stdout.lines().any(|line| line.trim() == name)
}

/// Whether phase 2 may create a kind cluster and load images into it.
///
/// A dry run must never provision: `--dry-run` promises to preview the plan
/// without mutating the store or the cluster.
fn should_provision_cluster(has_cluster: bool, skip_cluster: bool, dry_run: bool) -> bool {
    has_cluster && !skip_cluster && !dry_run
}

/// The kubeconfig context name kind uses for a cluster.
fn kind_context_name(name: &str) -> String {
    format!("kind-{name}")
}

/// Merge the resolved kubeconfig context into the deployer answers passed to
/// reconcile. Errors when the answers already pin a DIFFERENT context (silent
/// override would deploy to the wrong cluster), or when `answers` is not a
/// JSON object.
///
/// Matrix:
/// - `ctx` None => answers unchanged
/// - `answers` None + `ctx` Some => `{"kubeconfig_context": ctx}`
/// - object without the key => insert
/// - object with equal value => unchanged
/// - object with different value => `InvalidArgument` naming both
/// - non-object answers => `InvalidArgument`
#[cfg(any(feature = "k8s-client", test))]
fn merge_kubeconfig_context(
    answers: Option<Value>,
    ctx: Option<&str>,
) -> Result<Option<Value>, OpError> {
    let Some(ctx) = ctx else {
        return Ok(answers);
    };
    let Some(mut answers) = answers else {
        return Ok(Some(json!({ "kubeconfig_context": ctx })));
    };
    let obj = answers.as_object_mut().ok_or_else(|| {
        OpError::InvalidArgument("deployer answers must be a JSON object".to_string())
    })?;
    match obj.get("kubeconfig_context") {
        None => {
            obj.insert(
                "kubeconfig_context".to_string(),
                Value::String(ctx.to_string()),
            );
        }
        Some(existing) => {
            // `Value`'s Display renders the actual JSON, so a non-string answer
            // reports itself rather than collapsing to an empty string.
            if existing.as_str() != Some(ctx) {
                return Err(OpError::InvalidArgument(format!(
                    "deployer answers already set `kubeconfig_context` to `{existing}` \
                     but the cluster resolved context is `{ctx}`; \
                     remove the manifest's `kubeconfig_context` answer or set it to `{ctx}`"
                )));
            }
        }
    }
    Ok(Some(answers))
}

fn preflight_detail(outcome: &crate::tool_check::ToolCheckOutcome) -> String {
    use crate::tool_check::ToolCheckOutcome;
    match outcome {
        ToolCheckOutcome::Ok { .. } => String::new(),
        ToolCheckOutcome::Missing { install_hint } => {
            format!("not found. {install_hint}")
        }
        ToolCheckOutcome::VersionMismatch {
            found,
            required,
            install_hint,
        } => {
            format!("found {found}, need {required}. {install_hint}")
        }
        ToolCheckOutcome::AuthFailed {
            detail,
            recovery_hint,
        } => {
            format!("{detail}. {recovery_hint}")
        }
        ToolCheckOutcome::Unreachable {
            detail,
            recovery_hint,
        } => {
            format!("{detail}. {recovery_hint}")
        }
        ToolCheckOutcome::ProbeError { detail } => detail.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_cluster_exists_exact_match() {
        let stdout = "foo\nbar\nbaz\n";
        assert!(kind_cluster_exists(stdout, "bar"));
        assert!(!kind_cluster_exists(stdout, "ba"));
        assert!(!kind_cluster_exists(stdout, "barn"));
    }

    #[test]
    fn kind_cluster_exists_trims_whitespace() {
        let stdout = "  foo  \n  bar  \n";
        assert!(kind_cluster_exists(stdout, "foo"));
        assert!(kind_cluster_exists(stdout, "bar"));
    }

    #[test]
    fn kind_cluster_exists_empty_stdout() {
        assert!(!kind_cluster_exists("", "anything"));
        assert!(!kind_cluster_exists("\n", "anything"));
    }

    /// `--dry-run` promises not to mutate the store. A missing non-local env is
    /// the one place `up` would otherwise write before `apply` ever runs.
    #[cfg(feature = "k8s-client")]
    #[test]
    fn dry_run_does_not_create_a_missing_non_local_environment() {
        use crate::environment::EnvironmentStore as _;
        use greentic_deploy_spec::EnvId;

        let store_dir = tempfile::tempdir().unwrap();
        let store = LocalFsStore::new(store_dir.path());
        let registry = crate::env_packs::EnvPackRegistry::with_builtins();

        let manifest_dir = tempfile::tempdir().unwrap();
        let manifest_path = manifest_dir.path().join("env.json");
        let manifest = json!({
            "schema": crate::cli::env_manifest::ENV_MANIFEST_SCHEMA_V1,
            "environment": { "id": "staging", "tenant_org_id": "org-1" },
        });
        std::fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let flags = OpFlags {
            schema_only: false,
            answers: Some(manifest_path),
        };
        let args = EnvUpArgs {
            yes: true,
            non_interactive: true,
            dry_run: true,
            skip_cluster: false,
            no_port_forward: true,
            port: 8080,
            allow_missing_seeds: false,
            updated_by: None,
        };

        let env_id = EnvId::try_from("staging").unwrap();
        assert!(!store.exists(&env_id).unwrap());

        let (outcome, forward) = up(&store, &registry, &flags, args).expect("dry run succeeds");

        assert!(forward.is_none(), "dry run must not port-forward");
        assert_eq!(outcome.result["dry_run"], json!(true));
        assert!(
            !store.exists(&env_id).unwrap(),
            "dry run must not create the environment"
        );
    }

    #[test]
    fn should_provision_cluster_only_for_a_real_declared_unskipped_run() {
        // (has_cluster, skip_cluster, dry_run) -> provision
        assert!(should_provision_cluster(true, false, false));
        // A dry run never provisions, however the other flags are set.
        assert!(!should_provision_cluster(true, false, true));
        assert!(!should_provision_cluster(true, true, true));
        // No `cluster` block, or an explicit skip, means nothing to provision.
        assert!(!should_provision_cluster(false, false, false));
        assert!(!should_provision_cluster(true, true, false));
        assert!(!should_provision_cluster(false, true, true));
    }

    #[test]
    fn kind_context_name_formats_correctly() {
        assert_eq!(kind_context_name("my-cluster"), "kind-my-cluster");
        assert_eq!(kind_context_name("local"), "kind-local");
    }

    #[test]
    fn decide_missing_seed_matrix() {
        // Present in Vault always skips (a surviving Vault already holds it),
        // even under --allow-missing-seeds.
        assert_eq!(
            decide_missing_seed(true, false),
            MissingSeedAction::SkipPresent
        );
        assert_eq!(
            decide_missing_seed(true, true),
            MissingSeedAction::SkipPresent
        );
        // Absent (a fresh Vault always passes present=false, as does a surviving
        // Vault without the key): fail closed unless the escape hatch is set.
        assert_eq!(decide_missing_seed(false, false), MissingSeedAction::Fail);
        assert_eq!(decide_missing_seed(false, true), MissingSeedAction::Warn);
    }

    #[cfg(feature = "k8s-client")]
    #[test]
    fn evaluate_cluster_crb_preflight_allows_when_permitted_and_names_external_on_denial() {
        use crate::env_packs::k8s::credentials::{AccessDecision, OperationDecision};

        let allowed = vec![OperationDecision {
            operation: VAULT_CRB_CREATE_OP,
            decision: AccessDecision::Allowed,
        }];
        assert!(evaluate_cluster_crb_preflight(&allowed).is_ok());

        let denied = vec![OperationDecision {
            operation: VAULT_CRB_CREATE_OP,
            decision: AccessDecision::Denied("not cluster-admin".to_string()),
        }];
        let err = evaluate_cluster_crb_preflight(&denied).unwrap_err();
        match err {
            OpError::Conflict(msg) => {
                assert!(msg.contains("clusterrolebindings"), "{msg}");
                assert!(msg.contains("external"), "{msg}");
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn merge_kubeconfig_context_ctx_none_passes_through() {
        let answers = Some(json!({"namespace": "ns"}));
        let result = merge_kubeconfig_context(answers.clone(), None).unwrap();
        assert_eq!(result, answers);
    }

    #[test]
    fn merge_kubeconfig_context_both_none() {
        let result = merge_kubeconfig_context(None, None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn merge_kubeconfig_context_answers_none_ctx_some() {
        let result = merge_kubeconfig_context(None, Some("kind-local")).unwrap();
        assert_eq!(result, Some(json!({"kubeconfig_context": "kind-local"})));
    }

    #[test]
    fn merge_kubeconfig_context_inserts_missing_key() {
        let answers = Some(json!({"namespace": "ns"}));
        let result = merge_kubeconfig_context(answers, Some("kind-local")).unwrap();
        let obj = result.unwrap();
        assert_eq!(obj["kubeconfig_context"], "kind-local");
        assert_eq!(obj["namespace"], "ns");
    }

    #[test]
    fn merge_kubeconfig_context_equal_value_unchanged() {
        let answers = Some(json!({"kubeconfig_context": "kind-local"}));
        let result = merge_kubeconfig_context(answers, Some("kind-local")).unwrap();
        assert_eq!(result, Some(json!({"kubeconfig_context": "kind-local"})));
    }

    #[test]
    fn merge_kubeconfig_context_different_value_errors() {
        let answers = Some(json!({"kubeconfig_context": "prod-ctx"}));
        let err = merge_kubeconfig_context(answers, Some("kind-local")).unwrap_err();
        match err {
            OpError::InvalidArgument(msg) => {
                assert!(msg.contains("prod-ctx"), "msg: {msg}");
                assert!(msg.contains("kind-local"), "msg: {msg}");
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn merge_kubeconfig_context_non_object_errors() {
        let answers = Some(json!("not-an-object"));
        let err = merge_kubeconfig_context(answers, Some("kind-local")).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    // ── Phase 2 / access: the `kind` + `docker` + `kubectl` sequence ──────
    //
    // Driven through the `CommandRunner` seam, so the whole matrix (cluster
    // present/absent, every non-zero exit, spawn failure) is exercised without
    // either binary installed. Only the two thin `RealCommandRunner` wrappers
    // actually shell out.

    use crate::desktop::CommandRunner;
    use std::collections::VecDeque;
    use std::process::{Command, ExitStatus, Output};
    use std::sync::Mutex;

    /// A normal exit with `code`.
    fn exit_code(code: i32) -> ExitStatus {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            ExitStatus::from_raw(code << 8)
        }
        #[cfg(not(unix))]
        {
            use std::os::windows::process::ExitStatusExt;
            ExitStatus::from_raw(code as u32)
        }
    }

    fn captured(stdout: &str, code: i32) -> Result<Output, String> {
        Ok(Output {
            status: exit_code(code),
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        })
    }

    /// Records every argv and replays queued results in call order. An empty
    /// queue yields success, so a test only scripts the calls it cares about.
    #[derive(Default)]
    struct FakeRunner {
        calls: Mutex<Vec<Vec<String>>>,
        runs: Mutex<VecDeque<Result<ExitStatus, String>>>,
        outputs: Mutex<VecDeque<Result<Output, String>>>,
    }

    impl FakeRunner {
        fn with_runs(self, runs: Vec<Result<ExitStatus, String>>) -> Self {
            *self.runs.lock().unwrap() = runs.into();
            self
        }

        fn with_outputs(self, outputs: Vec<Result<Output, String>>) -> Self {
            *self.outputs.lock().unwrap() = outputs.into();
            self
        }

        fn argv(cmd: &Command) -> Vec<String> {
            std::iter::once(cmd.get_program().to_string_lossy().to_string())
                .chain(cmd.get_args().map(|a| a.to_string_lossy().to_string()))
                .collect()
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, cmd: &mut Command) -> anyhow::Result<ExitStatus> {
            self.calls.lock().unwrap().push(Self::argv(cmd));
            match self.runs.lock().unwrap().pop_front() {
                Some(Ok(status)) => Ok(status),
                Some(Err(msg)) => Err(anyhow::anyhow!(msg)),
                None => Ok(exit_code(0)),
            }
        }

        fn output(&self, cmd: &mut Command) -> anyhow::Result<Output> {
            self.calls.lock().unwrap().push(Self::argv(cmd));
            match self.outputs.lock().unwrap().pop_front() {
                Some(Ok(out)) => Ok(out),
                Some(Err(msg)) => Err(anyhow::anyhow!(msg)),
                None => Ok(Output {
                    status: exit_code(0),
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                }),
            }
        }
    }

    fn cluster_manifest(name: &str, ctx: Option<&str>, images: &[&str]) -> EnvManifest {
        let mut cluster = json!({
            "provider": "kind",
            "name": name,
            "load_images": images,
        });
        if let Some(ctx) = ctx {
            cluster["kubeconfig_context"] = json!(ctx);
        }
        serde_json::from_value(json!({
            "schema": crate::cli::env_manifest::ENV_MANIFEST_SCHEMA_V1,
            "environment": { "id": "local" },
            "cluster": cluster,
        }))
        .expect("valid cluster manifest")
    }

    #[test]
    fn ensure_kind_cluster_creates_missing_cluster_then_pulls_and_loads_images() {
        // `kind get clusters` lists someone else's cluster, not ours.
        let runner = FakeRunner::default().with_outputs(vec![captured("other\n", 0)]);
        let manifest = cluster_manifest("demo", None, &["img:1"]);

        let ctx = ensure_kind_cluster_with_runner(&manifest, &runner).unwrap();

        assert_eq!(ctx.as_deref(), Some("kind-demo"));
        assert_eq!(
            runner.calls(),
            vec![
                vec!["kind", "get", "clusters"],
                vec!["kind", "create", "cluster", "--name", "demo"],
                vec!["docker", "pull", "img:1"],
                vec!["kind", "load", "docker-image", "img:1", "--name", "demo"],
            ]
        );
    }

    /// Re-running `op env up` against a live cluster must not recreate it.
    #[test]
    fn ensure_kind_cluster_skips_create_when_the_cluster_already_exists() {
        let runner = FakeRunner::default().with_outputs(vec![captured("demo\n", 0)]);
        let manifest = cluster_manifest("demo", None, &[]);

        let ctx = ensure_kind_cluster_with_runner(&manifest, &runner).unwrap();

        assert_eq!(ctx.as_deref(), Some("kind-demo"));
        assert_eq!(runner.calls(), vec![vec!["kind", "get", "clusters"]]);
    }

    /// A failed listing yields empty stdout, which would otherwise read as "no
    /// such cluster" and blame the create that follows. The usual cause is a
    /// stopped Docker daemon, so the error has to say so.
    #[test]
    fn ensure_kind_cluster_fails_when_listing_exits_nonzero() {
        let runner = FakeRunner::default().with_outputs(vec![Ok(Output {
            status: exit_code(1),
            stdout: Vec::new(),
            stderr: b"cannot connect to the Docker daemon".to_vec(),
        })]);
        let manifest = cluster_manifest("demo", None, &[]);

        let err = ensure_kind_cluster_with_runner(&manifest, &runner).unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("Docker daemon"), "{msg}");
        assert!(msg.contains("cannot connect"), "{msg}");
        // It must not have gone on to create anything.
        assert_eq!(runner.calls(), vec![vec!["kind", "get", "clusters"]]);
    }

    /// A spawn failure (kind not on PATH) must keep the underlying io detail —
    /// `{e:#}` walks the runner's context chain.
    #[test]
    fn ensure_kind_cluster_surfaces_a_spawn_failure_with_its_cause() {
        let runner =
            FakeRunner::default().with_outputs(vec![Err("No such file or directory".to_string())]);
        let manifest = cluster_manifest("demo", None, &[]);

        let err = ensure_kind_cluster_with_runner(&manifest, &runner).unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("kind get clusters"), "{msg}");
        assert!(msg.contains("No such file or directory"), "{msg}");
    }

    #[test]
    fn ensure_kind_cluster_fails_when_create_exits_nonzero() {
        let runner = FakeRunner::default()
            .with_outputs(vec![captured("", 0)])
            .with_runs(vec![Ok(exit_code(1))]);
        let manifest = cluster_manifest("demo", None, &[]);

        let err = ensure_kind_cluster_with_runner(&manifest, &runner).unwrap_err();

        assert!(err.to_string().contains("kind create cluster"), "{err}");
    }

    #[test]
    fn ensure_kind_cluster_fails_when_docker_pull_exits_nonzero() {
        let runner = FakeRunner::default()
            .with_outputs(vec![captured("demo\n", 0)])
            .with_runs(vec![Ok(exit_code(1))]); // the pull
        let manifest = cluster_manifest("demo", None, &["img:1"]);

        let err = ensure_kind_cluster_with_runner(&manifest, &runner).unwrap_err();

        assert!(err.to_string().contains("docker pull img:1"), "{err}");
    }

    #[test]
    fn ensure_kind_cluster_fails_when_image_load_exits_nonzero() {
        let runner = FakeRunner::default()
            .with_outputs(vec![captured("demo\n", 0)])
            .with_runs(vec![Ok(exit_code(0)), Ok(exit_code(1))]); // pull ok, load fails
        let manifest = cluster_manifest("demo", None, &["img:1"]);

        let err = ensure_kind_cluster_with_runner(&manifest, &runner).unwrap_err();

        assert!(err.to_string().contains("kind load docker-image"), "{err}");
    }

    /// An explicit `kubeconfig_context` wins over the derived `kind-<name>`.
    #[test]
    fn ensure_kind_cluster_prefers_an_explicit_kubeconfig_context() {
        let runner = FakeRunner::default().with_outputs(vec![captured("demo\n", 0)]);
        let manifest = cluster_manifest("demo", Some("my-ctx"), &[]);

        let ctx = ensure_kind_cluster_with_runner(&manifest, &runner).unwrap();

        assert_eq!(ctx.as_deref(), Some("my-ctx"));
    }

    fn port_forward(context: Option<&str>) -> PortForward {
        PortForward {
            namespace: "gtc-local".to_string(),
            context: context.map(String::from),
            port: 9090,
        }
    }

    #[test]
    fn run_port_forward_targets_the_router_service_on_the_requested_port() {
        let runner = FakeRunner::default();

        run_port_forward_with_runner(&port_forward(Some("kind-demo")), &runner).unwrap();

        assert_eq!(
            runner.calls(),
            vec![vec![
                "kubectl",
                "--context",
                "kind-demo",
                "-n",
                "gtc-local",
                "port-forward",
                "svc/gtc-router",
                "9090:8080",
            ]]
        );
    }

    #[test]
    fn run_port_forward_omits_the_context_flag_when_none_is_resolved() {
        let runner = FakeRunner::default();

        run_port_forward_with_runner(&port_forward(None), &runner).unwrap();

        let call = &runner.calls()[0];
        assert!(!call.contains(&"--context".to_string()), "{call:?}");
    }

    /// Ctrl-C is the normal way to end a foreground forward, not a failure.
    #[test]
    fn run_port_forward_treats_sigint_exit_130_as_success() {
        let runner = FakeRunner::default().with_runs(vec![Ok(exit_code(130))]);

        run_port_forward_with_runner(&port_forward(None), &runner).unwrap();
    }

    /// A child killed by a signal has no exit code at all on unix.
    #[cfg(unix)]
    #[test]
    fn run_port_forward_treats_a_killed_child_as_success() {
        use std::os::unix::process::ExitStatusExt;
        // Low 7 bits = signal number, so `.code()` is None and `.signal()` is Some.
        let killed = ExitStatus::from_raw(2);
        assert!(killed.code().is_none(), "fixture must model a signal death");
        let runner = FakeRunner::default().with_runs(vec![Ok(killed)]);

        run_port_forward_with_runner(&port_forward(None), &runner).unwrap();
    }

    #[test]
    fn run_port_forward_fails_on_a_real_nonzero_exit() {
        let runner = FakeRunner::default().with_runs(vec![Ok(exit_code(1))]);

        let err = run_port_forward_with_runner(&port_forward(None), &runner).unwrap_err();

        assert!(err.to_string().contains("port-forward"), "{err}");
    }

    #[test]
    fn run_port_forward_surfaces_a_spawn_failure_with_its_cause() {
        let runner =
            FakeRunner::default().with_runs(vec![Err("No such file or directory".to_string())]);

        let err = run_port_forward_with_runner(&port_forward(None), &runner).unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("failed to spawn"), "{msg}");
        assert!(msg.contains("No such file or directory"), "{msg}");
    }

    // ── Phase 1: preflight reporting ─────────────────────────────────────

    #[test]
    fn preflight_detail_renders_every_outcome() {
        use crate::tool_check::ToolCheckOutcome;

        assert_eq!(
            preflight_detail(&ToolCheckOutcome::Ok { detail: None }),
            String::new()
        );
        assert_eq!(
            preflight_detail(&ToolCheckOutcome::Missing {
                install_hint: "brew install kind".to_string(),
            }),
            "not found. brew install kind"
        );
        assert_eq!(
            preflight_detail(&ToolCheckOutcome::VersionMismatch {
                found: "0.1.0".to_string(),
                required: ">=0.20".to_string(),
                install_hint: "upgrade it".to_string(),
            }),
            "found 0.1.0, need >=0.20. upgrade it"
        );
        assert_eq!(
            preflight_detail(&ToolCheckOutcome::AuthFailed {
                detail: "token expired".to_string(),
                recovery_hint: "log in again".to_string(),
            }),
            "token expired. log in again"
        );
        assert_eq!(
            preflight_detail(&ToolCheckOutcome::Unreachable {
                detail: "connection refused".to_string(),
                recovery_hint: "start the daemon".to_string(),
            }),
            "connection refused. start the daemon"
        );
        assert_eq!(
            preflight_detail(&ToolCheckOutcome::ProbeError {
                detail: "unparseable version".to_string(),
            }),
            "unparseable version"
        );
    }

    // ── `up` entry point ─────────────────────────────────────────────────

    fn up_args() -> EnvUpArgs {
        EnvUpArgs {
            yes: true,
            non_interactive: true,
            dry_run: false,
            skip_cluster: false,
            no_port_forward: true,
            port: 8080,
            allow_missing_seeds: false,
            updated_by: None,
        }
    }

    fn write_manifest(dir: &std::path::Path, manifest: &Value) -> std::path::PathBuf {
        let path = dir.join("env.json");
        std::fs::write(&path, serde_json::to_vec_pretty(manifest).unwrap()).unwrap();
        path
    }

    #[test]
    fn up_schema_only_describes_its_inputs_without_touching_the_store() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = LocalFsStore::new(store_dir.path());
        let registry = crate::env_packs::EnvPackRegistry::with_builtins();
        let flags = OpFlags {
            schema_only: true,
            answers: None,
        };

        let (outcome, forward) = up(&store, &registry, &flags, up_args()).unwrap();

        assert!(forward.is_none());
        assert!(
            outcome.result["input_schema"]
                .as_str()
                .unwrap()
                .contains("--answers"),
        );
    }

    #[test]
    fn up_without_answers_is_an_invalid_argument() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = LocalFsStore::new(store_dir.path());
        let registry = crate::env_packs::EnvPackRegistry::with_builtins();
        let flags = OpFlags {
            schema_only: false,
            answers: None,
        };

        let err = up(&store, &registry, &flags, up_args()).unwrap_err();

        match err {
            OpError::InvalidArgument(msg) => assert!(msg.contains("--answers"), "{msg}"),
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn up_rejects_a_malformed_environment_id() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let registry = crate::env_packs::EnvPackRegistry::with_builtins();
        let manifest_dir = tempfile::tempdir().unwrap();
        let path = write_manifest(
            manifest_dir.path(),
            &json!({
                "schema": crate::cli::env_manifest::ENV_MANIFEST_SCHEMA_V1,
                "environment": { "id": "Not A Valid Id", "tenant_org_id": "org-1" },
            }),
        );
        let flags = OpFlags {
            schema_only: false,
            answers: Some(path),
        };

        let err = up(&store, &registry, &flags, up_args()).unwrap_err();

        match err {
            OpError::InvalidArgument(msg) => assert!(msg.contains("environment.id"), "{msg}"),
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    /// Creating a non-local env without an org would start the runtime with a
    /// null org context, so `up` refuses before it writes anything.
    #[test]
    fn up_refuses_to_create_a_non_local_environment_without_a_tenant_org() {
        use crate::environment::EnvironmentStore as _;
        use greentic_deploy_spec::EnvId;

        let dir = tempfile::tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let registry = crate::env_packs::EnvPackRegistry::with_builtins();
        let manifest_dir = tempfile::tempdir().unwrap();
        let path = write_manifest(
            manifest_dir.path(),
            &json!({
                "schema": crate::cli::env_manifest::ENV_MANIFEST_SCHEMA_V1,
                "environment": { "id": "staging" },
            }),
        );
        let flags = OpFlags {
            schema_only: false,
            answers: Some(path),
        };

        let err = up(&store, &registry, &flags, up_args()).unwrap_err();

        match err {
            OpError::InvalidArgument(msg) => assert!(msg.contains("tenant_org_id"), "{msg}"),
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
        assert!(
            !store.exists(&EnvId::try_from("staging").unwrap()).unwrap(),
            "the refusal must not leave a half-created environment behind"
        );
    }
}
