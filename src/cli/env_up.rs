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
                     --no-port-forward, --port <u16>, --updated-by <STRING>"
                }),
            ),
            None,
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
    let skip_cluster = args.skip_cluster || !has_cluster;

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
    let ctx: Option<String> = if skip_cluster {
        manifest.cluster.as_ref().map(|c| {
            c.kubeconfig_context
                .clone()
                .unwrap_or_else(|| format!("kind-{}", c.name))
        })
    } else {
        ensure_kind_cluster(&manifest)?
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

    // ── Phase 5: reconcile + rollout ─────────────────────────────────
    let (report, namespace) = reconcile_phase(store, registry, &env_id, ctx.as_deref())?;

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

    Ok((
        OpOutcome::new(
            NOUN,
            "up",
            json!({
                "environment_id": env_id.as_str(),
                "applied_count": report.applied.len(),
                "pruned_count": report.pruned.len(),
                "applied": report.applied,
                "pruned": report.pruned,
            }),
        ),
        forward,
    ))
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

/// Block on a foreground `kubectl port-forward`. The child's stdout is
/// silenced (`Stdio::null`); our "Forwarding..." line goes to stderr.
/// A Ctrl-C (SIGINT) reaches both the child and us — treat exit 130 /
/// killed as success.
#[cfg(feature = "k8s-client")]
pub(crate) fn run_port_forward(pf: &PortForward) -> Result<(), OpError> {
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

    let status = cmd.status().map_err(|e| {
        OpError::Conflict(format!(
            "failed to spawn `kubectl port-forward`: {e}. \
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
    use std::process::Command;

    let cluster = manifest
        .cluster
        .as_ref()
        .expect("caller checks cluster.is_some()");
    let name = &cluster.name;

    // Check whether the cluster already exists.
    let list_output = Command::new("kind")
        .args(["get", "clusters"])
        .output()
        .map_err(|e| {
            OpError::Conflict(format!(
                "phase 2 (cluster): failed to run `kind get clusters`: {e}. \
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
        let status = Command::new("kind")
            .args(["create", "cluster", "--name", name])
            .status()
            .map_err(|e| {
                OpError::Conflict(format!(
                    "phase 2 (cluster): failed to run `kind create cluster`: {e}. \
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
        let status = Command::new("docker")
            .args(["pull", img])
            .status()
            .map_err(|e| {
                OpError::Conflict(format!(
                    "phase 2 (cluster): `docker pull {img}` failed: {e}. \
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
        let status = Command::new("kind")
            .args(["load", "docker-image", img, "--name", name])
            .status()
            .map_err(|e| {
                OpError::Conflict(format!(
                    "phase 2 (cluster): `kind load docker-image {img}` failed: {e}. \
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

/// The kubeconfig context name kind uses for a cluster.
#[cfg(any(feature = "k8s-client", test))]
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

    #[test]
    fn kind_context_name_formats_correctly() {
        assert_eq!(kind_context_name("my-cluster"), "kind-my-cluster");
        assert_eq!(kind_context_name("local"), "kind-local");
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
}
