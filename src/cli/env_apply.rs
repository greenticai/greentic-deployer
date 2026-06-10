//! `gtc op env apply` — declarative, upsert-only environment apply
//! (PR-1 of `plans/env-manifest-apply.md`).
//!
//! Consumes a `greentic.env-manifest.v1` document (via the standard
//! `--answers <PATH>` payload convention) and reconciles the environment
//! toward it: **validate → diff → plan → execute → verify**.
//!
//! - Upsert-only: resources in the store but absent from the manifest are
//!   left untouched. No pruning, no deletes (v1 decision).
//! - Wiring only: the manifest starts at "artifacts exist" — no pack or
//!   bundle building.
//! - Safe re-run: a second apply of an unchanged manifest is a visible
//!   no-op; a re-run after a partial failure completes the remainder
//!   (fail-fast, no rollback — every composed verb leaves the store valid,
//!   so the store itself is the checkpoint).
//! - Cross-step references resolve in-process: `add-endpoint` returns the
//!   store-assigned `endpoint_id`, which the subsequent `link-endpoint` /
//!   `set-welcome-flow` steps consume — no output-capture plumbing.
//! - Deterministic idempotency keys: derived from
//!   `(schema, env, step kind, natural key, desired-state hash)` so a
//!   re-run replays instead of double-mutating (HTTP-store dedupe
//!   compatible). Exception: `deploy`'s traffic cut-over key intentionally
//!   stays per-revision-derived — a re-stage is by definition a new
//!   cut-over.
//! - Store-level verify only: *runtime* readiness (secrets resolvable by
//!   the reader, routes served) is `gtc doctor`'s job — apply must work
//!   without a running runtime.
//!
//! Every mutation is executed through the existing single-purpose verb
//! functions (`deploy::deploy`, `bundles::update`, `messaging::add`/…,
//! `trust_root::bootstrap`, `env::init`/`set_public_url`), so audit,
//! authorization, signing, and revenue-policy logic stay single-sourced —
//! each step lands its own audit event under the composed verb's noun.
//!
//! Human-readable plan/progress lines go to **stderr**; stdout carries only
//! the standard `{op, noun, result}` JSON envelope (so the output is
//! already machine-readable — no separate `--json` flag).

use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use greentic_deploy_spec::{
    CustomerId, DeploymentId, EnvId, Environment, MessagingEndpoint, RouteBinding,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::environment::{EnvironmentStore, LocalFsStore, trust_root as store_trust_root};

use super::bundles::{BundleUpdatePayload, into_route_binding};
use super::deploy::BundleDeployPayload;
use super::env::EnvInitPayload;
use super::env_manifest::{
    ENV_MANIFEST_SCHEMA_V1, EnvManifest, ManifestEndpoint, ManifestWelcomeFlow, TrustRootDirective,
    manifest_schema,
};
use super::messaging::{
    EndpointAddPayload, EndpointLinkBundlePayload, EndpointSetWelcomeFlowPayload, EndpointSummary,
};
use super::trust_root::TrustRootBootstrapPayload;
use super::{OpError, OpFlags, OpOutcome};

const NOUN: &str = "env";
const VERB: &str = "apply";

/// Audit principal stamped on every composed mutation when the caller
/// doesn't pass `--updated-by`.
const DEFAULT_UPDATED_BY: &str = "env-apply";

// --- plan model ---------------------------------------------------------------

/// What the diff decided for one step. `Put` (secrets, cannot-diff) arrives
/// with PR-2; warning-carrying no-ops surface through the plan's `warnings`
/// list instead of a dedicated `Skip` action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ApplyAction {
    Create,
    Update,
    NoOp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ApplyStepKind {
    EnsureEnvironment,
    BootstrapTrustRoot,
    DeployBundle,
    UpdateBundle,
    AddEndpoint,
    LinkEndpoint,
    SetWelcomeFlow,
}

impl ApplyStepKind {
    fn label(self) -> &'static str {
        match self {
            ApplyStepKind::EnsureEnvironment => "ensure-environment",
            ApplyStepKind::BootstrapTrustRoot => "bootstrap-trust-root",
            ApplyStepKind::DeployBundle => "deploy-bundle",
            ApplyStepKind::UpdateBundle => "update-bundle",
            ApplyStepKind::AddEndpoint => "add-endpoint",
            ApplyStepKind::LinkEndpoint => "link-endpoint",
            ApplyStepKind::SetWelcomeFlow => "set-welcome-flow",
        }
    }
}

/// Reference to an endpoint that may not exist yet at plan time. `Created`
/// is resolved in-process during execution from the `add-endpoint` outcome.
#[derive(Debug, Clone)]
enum EndpointRef {
    Existing(String),
    CreatedByName(String),
}

/// The typed mutation a step performs at execute time. `None` for no-ops.
#[derive(Debug, Clone)]
enum StepOp {
    None,
    EnvInit {
        public_base_url: Option<String>,
    },
    SetPublicUrl {
        url: String,
    },
    TrustRootBootstrap,
    Deploy {
        payload: Box<BundleDeployPayload>,
        /// Digest recorded at plan time; re-verified just before the deploy
        /// step executes to shrink the validate→execute TOCTOU window.
        expected_digest: String,
    },
    BundleUpdate(Box<BundleUpdatePayload>),
    EndpointAdd(Box<EndpointAddPayload>),
    EndpointLink {
        endpoint: EndpointRef,
        bundle_id: String,
        idempotency_key: String,
    },
    WelcomeFlow {
        endpoint: EndpointRef,
        flow: ManifestWelcomeFlow,
        idempotency_key: String,
    },
}

#[derive(Debug, Clone)]
struct ApplyStep {
    kind: ApplyStepKind,
    key: String,
    action: ApplyAction,
    detail: String,
    idempotency_key: Option<String>,
    op: StepOp,
}

impl ApplyStep {
    fn no_op(kind: ApplyStepKind, key: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            kind,
            key: key.into(),
            action: ApplyAction::NoOp,
            detail: detail.into(),
            idempotency_key: None,
            op: StepOp::None,
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "kind": self.kind.label(),
            "key": self.key,
            "action": self.action,
            "detail": self.detail,
            "idempotency_key": self.idempotency_key,
        })
    }
}

// --- validated context ---------------------------------------------------------

/// Per-bundle resolved artifact (parallel to `manifest.bundles`).
struct BundleArtifact {
    resolved_path: PathBuf,
    digest: String,
    /// Billing principal resolved during validation (from
    /// `resolve_customer_id`). Used to match deployments by the same
    /// `(bundle_id, customer_id)` pair that `op deploy` keys on.
    customer_id: CustomerId,
}

/// Everything validation established, handed to diff/execute/verify.
struct ApplyContext {
    env_id: EnvId,
    manifest: EnvManifest,
    artifacts: Vec<BundleArtifact>,
    env: Option<Environment>,
    /// Canonicalized `environment.public_base_url` (validated form).
    canonical_public_base_url: Option<String>,
    warnings: Vec<String>,
    updated_by: String,
}

// --- entry point ----------------------------------------------------------------

/// `gtc op env apply --answers <manifest.json> [--dry-run] [--updated-by <who>] [--yes]`.
pub fn apply(
    store: &LocalFsStore,
    flags: &OpFlags,
    dry_run: bool,
    updated_by: Option<String>,
    yes: bool,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, VERB, manifest_schema()));
    }
    let manifest_path = flags.answers.clone().ok_or_else(|| {
        OpError::InvalidArgument(
            "env apply requires `--answers <manifest.json>` (a greentic.env-manifest.v1 \
             document; see `gtc op env apply --schema`)"
                .to_string(),
        )
    })?;
    let manifest: EnvManifest = super::load_answers(&manifest_path)?;
    manifest.validate_shape()?;
    let manifest_dir = manifest_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let updated_by = updated_by.unwrap_or_else(|| DEFAULT_UPDATED_BY.to_string());

    let ctx = resolve_and_validate(store, manifest, &manifest_dir, updated_by)?;
    let steps = diff(store, &ctx)?;
    render_plan(&steps, &ctx.warnings);

    let pending = steps
        .iter()
        .filter(|s| s.action != ApplyAction::NoOp)
        .count();
    if dry_run {
        return Ok(OpOutcome::new(
            NOUN,
            VERB,
            report_json(&ctx, &steps, "dry-run", None),
        ));
    }
    if pending > 0 && !yes && std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        eprint!(
            "apply {pending} change(s) to env `{}`? [y/N] ",
            ctx.env_id.as_str()
        );
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|source| OpError::Io {
                path: PathBuf::from("<stdin>"),
                source,
            })?;
        let answer = line.trim().to_ascii_lowercase();
        if answer != "y" && answer != "yes" {
            return Err(OpError::InvalidArgument(
                "aborted by user (pass --yes to skip the confirmation)".to_string(),
            ));
        }
    }

    execute(store, &ctx, &steps)?;
    let verify = verify(store, &ctx)?;
    Ok(OpOutcome::new(
        NOUN,
        VERB,
        report_json(&ctx, &steps, "apply", Some(verify)),
    ))
}

// --- validate -------------------------------------------------------------------

fn resolve_and_validate(
    store: &LocalFsStore,
    manifest: EnvManifest,
    manifest_dir: &Path,
    updated_by: String,
) -> Result<ApplyContext, OpError> {
    let env_id = EnvId::try_from(manifest.environment.id.as_str())
        .map_err(|e| OpError::InvalidArgument(format!("environment.id: {e}")))?;
    let canonical_public_base_url =
        super::env::parse_optional_public_base_url(&manifest.environment.public_base_url)?;

    let env = if store.exists(&env_id)? {
        Some(store.load(&env_id)?)
    } else {
        if env_id.as_str() != crate::defaults::LOCAL_ENV_ID {
            return Err(OpError::NotFound(format!(
                "environment `{env_id}` not found — v1 `env apply` bootstraps only the \
                 `local` environment; create `{env_id}` first with `gtc op env create`"
            )));
        }
        None
    };

    // Bundle artifacts: existence + digest, plus the B10 billing-principal
    // rule, all before any mutation.
    let mut artifacts = Vec::with_capacity(manifest.bundles.len());
    for b in &manifest.bundles {
        let resolved_path = if b.bundle_path.is_absolute() {
            b.bundle_path.clone()
        } else {
            manifest_dir.join(&b.bundle_path)
        };
        if !resolved_path.is_file() {
            return Err(OpError::InvalidArgument(format!(
                "bundle `{}`: `{}` is not a file (relative paths resolve against the \
                 manifest's directory)",
                b.bundle_id,
                resolved_path.display()
            )));
        }
        let digest =
            super::bundle_stage::sha256_file(&resolved_path).map_err(|source| OpError::Io {
                path: resolved_path.clone(),
                source,
            })?;
        let customer_id = super::bundles::resolve_customer_id(&env_id, b.customer_id.clone())?;
        artifacts.push(BundleArtifact {
            resolved_path,
            digest,
            customer_id,
        });
    }

    // Deployment natural-key sanity: `op deploy` keys on
    // `(bundle_id, customer_id)`. Refuse to adopt a deployment owned by a
    // different billing principal, and reject same-pair ambiguity.
    if let Some(env) = &env {
        for (b, artifact) in manifest.bundles.iter().zip(&artifacts) {
            let same_customer: Vec<_> = env
                .bundles
                .iter()
                .filter(|d| {
                    d.bundle_id.as_str() == b.bundle_id && d.customer_id == artifact.customer_id
                })
                .collect();
            let other_customer: Vec<_> = env
                .bundles
                .iter()
                .filter(|d| {
                    d.bundle_id.as_str() == b.bundle_id && d.customer_id != artifact.customer_id
                })
                .collect();
            if !other_customer.is_empty() {
                return Err(OpError::Conflict(format!(
                    "bundle `{}`: deployment owned by customer `{}` exists but manifest \
                     resolves to `{}` — apply refuses to adopt a deployment owned by a \
                     different customer",
                    b.bundle_id,
                    other_customer[0].customer_id.as_str(),
                    artifact.customer_id.as_str(),
                )));
            }
            if same_customer.len() > 1 {
                return Err(OpError::Conflict(format!(
                    "bundle `{}` matches {} deployments for customer `{}` in env `{env_id}` \
                     — apply refuses to guess; reconcile with `gtc op bundles list {env_id}` \
                     first",
                    b.bundle_id,
                    same_customer.len(),
                    artifact.customer_id.as_str(),
                )));
            }
        }
    }

    let mut warnings = Vec::new();

    // Endpoint link targets + match ambiguity + welcome-flow reachability.
    for ep in &manifest.messaging_endpoints {
        for link in &ep.links {
            let in_manifest = manifest.bundles.iter().any(|b| &b.bundle_id == link);
            if in_manifest {
                continue;
            }
            let in_env = env
                .as_ref()
                .is_some_and(|e| e.bundles.iter().any(|d| d.bundle_id.as_str() == link));
            if in_env {
                warnings.push(format!(
                    "endpoint `{}`: link `{link}` is satisfied only by a pre-existing env \
                     deployment (not declared in this manifest)",
                    ep.name
                ));
            } else {
                return Err(OpError::InvalidArgument(format!(
                    "endpoint `{}`: link `{link}` is neither declared in this manifest's \
                     bundles[] nor deployed in env `{env_id}`",
                    ep.name
                )));
            }
        }

        let matched = match &env {
            Some(e) => match_existing_endpoint(e, ep)?,
            None => None,
        };
        if let Some(wf) = &ep.welcome_flow {
            let linked_via_manifest = ep.links.contains(&wf.bundle_id);
            let linked_on_existing = matched
                .is_some_and(|m| m.linked_bundles.iter().any(|b| b.as_str() == wf.bundle_id));
            if !linked_via_manifest && !linked_on_existing {
                return Err(OpError::InvalidArgument(format!(
                    "endpoint `{}`: welcome_flow.bundle_id `{}` must be in this endpoint's \
                     links[] (or already linked on the matched endpoint)",
                    ep.name, wf.bundle_id
                )));
            }
        }
        if let Some(m) = matched {
            let existing_refs: Vec<String> = m
                .secret_refs
                .iter()
                .map(|r| r.as_str().to_string())
                .collect();
            if !ep.secret_refs.is_empty() && ep.secret_refs != existing_refs {
                warnings.push(format!(
                    "endpoint `{}`: secret_refs differ from the existing endpoint's — \
                     left untouched (no endpoint update verb exists yet)",
                    ep.name
                ));
            }
        }
    }

    Ok(ApplyContext {
        env_id,
        manifest,
        artifacts,
        env,
        canonical_public_base_url,
        warnings,
        updated_by,
    })
}

/// Match an existing endpoint by the `(provider_type, display_name)` natural
/// key. More than one pair match = ambiguity error; a display-name match
/// with a different `provider_type` = repurposed-name error (apply refuses
/// to guess).
fn match_existing_endpoint<'e>(
    env: &'e Environment,
    ep: &ManifestEndpoint,
) -> Result<Option<&'e MessagingEndpoint>, OpError> {
    let name_matches: Vec<&MessagingEndpoint> = env
        .messaging_endpoints
        .iter()
        .filter(|m| m.display_name == ep.name)
        .collect();
    let pair_matches: Vec<&&MessagingEndpoint> = name_matches
        .iter()
        .filter(|m| m.provider_type == ep.provider_type)
        .collect();
    match pair_matches.len() {
        0 if name_matches.is_empty() => Ok(None),
        0 => Err(OpError::Conflict(format!(
            "endpoint `{}`: an endpoint with this display_name exists but with \
             provider_type `{}` (manifest says `{}`) — apply refuses to repurpose a name; \
             rename or remove the existing endpoint first",
            ep.name, name_matches[0].provider_type, ep.provider_type
        ))),
        1 => Ok(Some(pair_matches[0])),
        n => Err(OpError::Conflict(format!(
            "endpoint `{}`: {n} existing endpoints match (provider_type=`{}`, \
             display_name=`{}`): [{}] — apply refuses to guess; remove the duplicates first",
            ep.name,
            ep.provider_type,
            ep.name,
            pair_matches
                .iter()
                .map(|m| m.endpoint_id.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

// --- diff -----------------------------------------------------------------------

fn diff(store: &LocalFsStore, ctx: &ApplyContext) -> Result<Vec<ApplyStep>, OpError> {
    let mut steps = Vec::new();
    let env_id_str = ctx.env_id.as_str().to_string();

    // 1. EnsureEnvironment.
    match &ctx.env {
        None => steps.push(ApplyStep {
            kind: ApplyStepKind::EnsureEnvironment,
            key: env_id_str.clone(),
            action: ApplyAction::Create,
            detail: "env init (local bootstrap: default env-pack bindings + trust-root seed)"
                .to_string(),
            idempotency_key: None,
            op: StepOp::EnvInit {
                public_base_url: ctx.canonical_public_base_url.clone(),
            },
        }),
        Some(env) => match &ctx.canonical_public_base_url {
            Some(url) if env.host_config.public_base_url.as_deref() != Some(url.as_str()) => {
                steps.push(ApplyStep {
                    kind: ApplyStepKind::EnsureEnvironment,
                    key: env_id_str.clone(),
                    action: ApplyAction::Update,
                    detail: format!("set-public-url {url}"),
                    idempotency_key: None,
                    op: StepOp::SetPublicUrl { url: url.clone() },
                });
            }
            _ => steps.push(ApplyStep::no_op(
                ApplyStepKind::EnsureEnvironment,
                env_id_str.clone(),
                "exists (public_base_url unchanged)",
            )),
        },
    }

    // 2. BootstrapTrustRoot.
    if ctx.manifest.trust_root == Some(TrustRootDirective::Bootstrap) {
        steps.push(trust_root_step(store, ctx)?);
    }

    // 3. Bundles (keyed on `(bundle_id, customer_id)` — the same natural key
    //    that `op deploy` uses).
    for (b, artifact) in ctx.manifest.bundles.iter().zip(&ctx.artifacts) {
        let existing = ctx.env.as_ref().and_then(|e| {
            e.bundles.iter().find(|d| {
                d.bundle_id.as_str() == b.bundle_id && d.customer_id == artifact.customer_id
            })
        });
        match existing {
            None => {
                let detail = format!(
                    "{} → {}",
                    short_digest(&artifact.digest),
                    binding_summary(&b.route_binding.clone().map(into_route_binding))
                );
                steps.push(ApplyStep {
                    kind: ApplyStepKind::DeployBundle,
                    key: b.bundle_id.clone(),
                    action: ApplyAction::Create,
                    detail,
                    idempotency_key: None, // deploy derives its cut-over key per revision
                    op: StepOp::Deploy {
                        payload: Box::new(BundleDeployPayload {
                            environment_id: env_id_str.clone(),
                            bundle_id: b.bundle_id.clone(),
                            customer_id: b.customer_id.clone(),
                            bundle_path: Some(artifact.resolved_path.clone()),
                            idempotency_key: None,
                            config_overrides: b.config_overrides.clone(),
                            route_binding: b.route_binding.clone(),
                        }),
                        expected_digest: artifact.digest.clone(),
                    },
                });
            }
            Some(dep) => {
                let desired_binding: Option<RouteBinding> =
                    b.route_binding.clone().map(into_route_binding);
                let binding_differs = desired_binding
                    .as_ref()
                    .is_some_and(|rb| *rb != dep.route_binding);
                let overrides_differ = b
                    .config_overrides
                    .as_ref()
                    .is_some_and(|o| *o != dep.config_overrides);
                let env = ctx.env.as_ref().expect("existing deployment implies env");
                let converged = deployment_converged(env, dep.deployment_id, &artifact.digest);
                let needs_deploy = !converged;
                let live = live_revision_digest(env, dep.deployment_id);

                // Deploy FIRST when re-staging is needed (routing-metadata-
                // last: a stage failure leaves the OLD revision serving under
                // the OLD binding, keeping published paths alive). The
                // binding/overrides update runs AFTER the deploy lands.
                if needs_deploy {
                    let detail = if converged {
                        // Unreachable (needs_deploy == !converged), but kept
                        // for defensive completeness.
                        format!(
                            "digest {} → {} (blue-green re-stage)",
                            live.map(short_digest).unwrap_or("none"),
                            short_digest(&artifact.digest)
                        )
                    } else if live.is_some_and(digest_is_real) {
                        format!(
                            "digest {} → {} (blue-green re-stage)",
                            live.map(short_digest).unwrap_or("none"),
                            short_digest(&artifact.digest)
                        )
                    } else {
                        format!(
                            "traffic split is not a single 100% entry \
                             → re-deploy reconverges ({})",
                            short_digest(&artifact.digest)
                        )
                    };
                    steps.push(ApplyStep {
                        kind: ApplyStepKind::DeployBundle,
                        key: b.bundle_id.clone(),
                        action: ApplyAction::Update,
                        detail,
                        idempotency_key: None,
                        op: StepOp::Deploy {
                            payload: Box::new(BundleDeployPayload {
                                environment_id: env_id_str.clone(),
                                bundle_id: b.bundle_id.clone(),
                                customer_id: b.customer_id.clone(),
                                bundle_path: Some(artifact.resolved_path.clone()),
                                idempotency_key: None,
                                // Overrides ride the deploy (applied after
                                // stage+warm, before the cut-over). The
                                // binding is reconciled by the update step
                                // AFTER the deploy lands, so None here —
                                // deploy rejects a differing binding.
                                config_overrides: b.config_overrides.clone(),
                                route_binding: None,
                            }),
                            expected_digest: artifact.digest.clone(),
                        },
                    });
                }

                if binding_differs || (overrides_differ && !needs_deploy) {
                    let route_binding = binding_differs.then(|| {
                        b.route_binding
                            .clone()
                            .expect("binding_differs implies manifest binding")
                    });
                    let config_overrides = (overrides_differ && !needs_deploy)
                        .then(|| b.config_overrides.clone().expect("overrides_differ"));
                    let desired_hash = hash_json(&json!({
                        "route_binding": route_binding,
                        "config_overrides": config_overrides,
                    }));
                    let ikey = derive_idempotency_key(
                        &ctx.env_id,
                        ApplyStepKind::UpdateBundle.label(),
                        &b.bundle_id,
                        &desired_hash,
                    );
                    let mut what = Vec::new();
                    if binding_differs {
                        what.push(format!("binding → {}", binding_summary(&desired_binding)));
                    }
                    if config_overrides.is_some() {
                        what.push("config_overrides".to_string());
                    }
                    steps.push(ApplyStep {
                        kind: ApplyStepKind::UpdateBundle,
                        key: b.bundle_id.clone(),
                        action: ApplyAction::Update,
                        detail: what.join(", "),
                        idempotency_key: Some(ikey.clone()),
                        op: StepOp::BundleUpdate(Box::new(BundleUpdatePayload {
                            environment_id: env_id_str.clone(),
                            deployment_id: dep.deployment_id.to_string(),
                            status: None,
                            route_binding,
                            revenue_share: None,
                            config_overrides,
                            idempotency_key: Some(ikey),
                        })),
                    });
                }

                if !needs_deploy && !binding_differs && !overrides_differ {
                    steps.push(ApplyStep::no_op(
                        ApplyStepKind::DeployBundle,
                        b.bundle_id.clone(),
                        format!("digest match ({})", short_digest(&artifact.digest)),
                    ));
                }
            }
        }
    }

    // 4. Endpoints (add → link → welcome-flow, per endpoint in manifest order).
    for ep in &ctx.manifest.messaging_endpoints {
        let matched = match &ctx.env {
            Some(e) => match_existing_endpoint(e, ep)?,
            None => None,
        };
        let endpoint_ref = match matched {
            Some(m) => EndpointRef::Existing(m.endpoint_id.to_string()),
            None => EndpointRef::CreatedByName(ep.name.clone()),
        };

        match matched {
            None => {
                let desired_hash = hash_json(&json!({
                    "provider_type": ep.provider_type,
                    "secret_refs": ep.secret_refs,
                }));
                let ikey = derive_idempotency_key(
                    &ctx.env_id,
                    ApplyStepKind::AddEndpoint.label(),
                    &ep.name,
                    &desired_hash,
                );
                steps.push(ApplyStep {
                    kind: ApplyStepKind::AddEndpoint,
                    key: ep.name.clone(),
                    action: ApplyAction::Create,
                    detail: format!("{} (provider_id = name)", ep.provider_type),
                    idempotency_key: Some(ikey.clone()),
                    op: StepOp::EndpointAdd(Box::new(EndpointAddPayload {
                        environment_id: env_id_str.clone(),
                        provider_id: ep.name.clone(),
                        provider_type: ep.provider_type.clone(),
                        display_name: ep.name.clone(),
                        secret_refs: ep.secret_refs.clone(),
                        idempotency_key: Some(ikey),
                        updated_by: ctx.updated_by.clone(),
                    })),
                });
            }
            Some(m) => steps.push(ApplyStep::no_op(
                ApplyStepKind::AddEndpoint,
                ep.name.clone(),
                format!("matched endpoint {}", m.endpoint_id),
            )),
        }

        for link in &ep.links {
            let already_linked =
                matched.is_some_and(|m| m.linked_bundles.iter().any(|b| b.as_str() == *link));
            let key = format!("{} → {link}", ep.name);
            if already_linked {
                steps.push(ApplyStep::no_op(ApplyStepKind::LinkEndpoint, key, "linked"));
            } else {
                let ikey = derive_idempotency_key(
                    &ctx.env_id,
                    ApplyStepKind::LinkEndpoint.label(),
                    &format!("{}\u{0}{link}", ep.name),
                    "",
                );
                steps.push(ApplyStep {
                    kind: ApplyStepKind::LinkEndpoint,
                    key,
                    action: ApplyAction::Create,
                    detail: String::new(),
                    idempotency_key: Some(ikey.clone()),
                    op: StepOp::EndpointLink {
                        endpoint: endpoint_ref.clone(),
                        bundle_id: link.clone(),
                        idempotency_key: ikey,
                    },
                });
            }
        }

        if let Some(wf) = &ep.welcome_flow {
            let current_equal = matched.is_some_and(|m| {
                m.welcome_flow.as_ref().is_some_and(|cur| {
                    cur.bundle_id.as_str() == wf.bundle_id
                        && cur.pack_id.as_str() == wf.pack_id
                        && cur.flow_id == wf.flow_id
                })
            });
            if current_equal {
                steps.push(ApplyStep::no_op(
                    ApplyStepKind::SetWelcomeFlow,
                    ep.name.clone(),
                    format!("{}/{}/{}", wf.bundle_id, wf.pack_id, wf.flow_id),
                ));
            } else {
                let desired_hash = hash_json(&json!({
                    "bundle_id": wf.bundle_id, "pack_id": wf.pack_id, "flow_id": wf.flow_id,
                }));
                let ikey = derive_idempotency_key(
                    &ctx.env_id,
                    ApplyStepKind::SetWelcomeFlow.label(),
                    &ep.name,
                    &desired_hash,
                );
                let action = if matched.is_some_and(|m| m.welcome_flow.is_some()) {
                    ApplyAction::Update
                } else {
                    ApplyAction::Create
                };
                steps.push(ApplyStep {
                    kind: ApplyStepKind::SetWelcomeFlow,
                    key: ep.name.clone(),
                    action,
                    detail: format!("{}/{}/{}", wf.bundle_id, wf.pack_id, wf.flow_id),
                    idempotency_key: Some(ikey.clone()),
                    op: StepOp::WelcomeFlow {
                        endpoint: endpoint_ref.clone(),
                        flow: wf.clone(),
                        idempotency_key: ikey,
                    },
                });
            }
        }
    }

    Ok(steps)
}

/// Trust-root diff: read-only — `load_existing_only` never generates a key,
/// so `--dry-run` leaves the disk untouched. A missing operator key plans as
/// `create` (bootstrap generates it at execute time).
fn trust_root_step(store: &LocalFsStore, ctx: &ApplyContext) -> Result<ApplyStep, OpError> {
    let key = ctx.env_id.as_str().to_string();
    let Some(_env) = &ctx.env else {
        return Ok(ApplyStep {
            kind: ApplyStepKind::BootstrapTrustRoot,
            key,
            action: ApplyAction::Create,
            detail: "bootstrap (fresh env)".to_string(),
            idempotency_key: None,
            op: StepOp::TrustRootBootstrap,
        });
    };
    let env_dir = store.env_dir(&ctx.env_id)?;
    let trust_root = store_trust_root::load(&env_dir)?;
    let operator_key = crate::operator_key::load_existing_only();
    let (action, detail, op) = match operator_key {
        Ok(k)
            if trust_root
                .keys
                .iter()
                .any(|t| t.key_id.eq_ignore_ascii_case(&k.key_id)) =>
        {
            (
                ApplyAction::NoOp,
                format!("operator key {} already trusted", short_key_id(&k.key_id)),
                StepOp::None,
            )
        }
        Ok(k) => (
            ApplyAction::Create,
            format!("trust operator key {}", short_key_id(&k.key_id)),
            StepOp::TrustRootBootstrap,
        ),
        Err(_) => (
            ApplyAction::Create,
            "operator key will be generated".to_string(),
            StepOp::TrustRootBootstrap,
        ),
    };
    Ok(ApplyStep {
        kind: ApplyStepKind::BootstrapTrustRoot,
        key,
        action,
        detail,
        idempotency_key: None,
        op,
    })
}

// --- execute --------------------------------------------------------------------

fn execute(store: &LocalFsStore, ctx: &ApplyContext, steps: &[ApplyStep]) -> Result<(), OpError> {
    // Sub-verbs get clean flags: payloads are passed directly, never re-read
    // from the manifest path.
    let exec_flags = OpFlags::default();
    let mut created_endpoints: BTreeMap<String, String> = BTreeMap::new();
    let total = steps.len();

    for (i, step) in steps.iter().enumerate() {
        let n = i + 1;
        if step.action == ApplyAction::NoOp {
            eprintln!(
                "[{n}/{total}] {:<22} {:<40} no-op",
                step.kind.label(),
                step.key
            );
            continue;
        }
        eprintln!(
            "[{n}/{total}] {:<22} {:<40} {}…",
            step.kind.label(),
            step.key,
            match step.action {
                ApplyAction::Create => "create",
                ApplyAction::Update => "update",
                ApplyAction::NoOp => unreachable!(),
            }
        );
        let result: Result<(), OpError> = match &step.op {
            StepOp::None => Ok(()),
            StepOp::EnvInit { public_base_url } => super::env::init(
                store,
                &exec_flags,
                EnvInitPayload {
                    public_base_url: public_base_url.clone(),
                },
            )
            .map(|_| ()),
            StepOp::SetPublicUrl { url } => {
                super::env::set_public_url(store, &exec_flags, ctx.env_id.as_str(), url).map(|_| ())
            }
            StepOp::TrustRootBootstrap => super::trust_root::bootstrap(
                store,
                &exec_flags,
                Some(TrustRootBootstrapPayload {
                    environment_id: ctx.env_id.as_str().to_string(),
                }),
            )
            .map(|_| ()),
            StepOp::Deploy {
                payload,
                expected_digest,
            } => {
                ensure_artifact_unchanged(
                    payload
                        .bundle_path
                        .as_deref()
                        .expect("apply-built Deploy always has bundle_path"),
                    expected_digest,
                )?;
                super::deploy::deploy(store, &exec_flags, Some((**payload).clone())).map(|_| ())
            }
            StepOp::BundleUpdate(payload) => {
                super::bundles::update(store, &exec_flags, Some((**payload).clone())).map(|_| ())
            }
            StepOp::EndpointAdd(payload) => super::messaging::add(
                store,
                &exec_flags,
                Some((**payload).clone()),
            )
            .map(|outcome| {
                if let Ok(summary) = serde_json::from_value::<EndpointSummary>(outcome.result) {
                    created_endpoints.insert(payload.display_name.clone(), summary.endpoint_id);
                }
            }),
            StepOp::EndpointLink {
                endpoint,
                bundle_id,
                idempotency_key,
            } => resolve_endpoint_id(endpoint, &created_endpoints).and_then(|endpoint_id| {
                super::messaging::link_bundle(
                    store,
                    &exec_flags,
                    Some(EndpointLinkBundlePayload {
                        environment_id: ctx.env_id.as_str().to_string(),
                        endpoint_id,
                        bundle_id: bundle_id.clone(),
                        idempotency_key: Some(idempotency_key.clone()),
                        updated_by: ctx.updated_by.clone(),
                    }),
                )
                .map(|_| ())
            }),
            StepOp::WelcomeFlow {
                endpoint,
                flow,
                idempotency_key,
            } => resolve_endpoint_id(endpoint, &created_endpoints).and_then(|endpoint_id| {
                super::messaging::set_welcome_flow(
                    store,
                    &exec_flags,
                    Some(EndpointSetWelcomeFlowPayload {
                        environment_id: ctx.env_id.as_str().to_string(),
                        endpoint_id,
                        bundle_id: flow.bundle_id.clone(),
                        pack_id: flow.pack_id.clone(),
                        flow_id: flow.flow_id.clone(),
                        idempotency_key: Some(idempotency_key.clone()),
                        updated_by: ctx.updated_by.clone(),
                    }),
                )
                .map(|_| ())
            }),
        };
        if let Err(err) = result {
            let remaining = total - n;
            eprintln!(
                "apply: step {n}/{total} `{} {}` failed; {remaining} step(s) not attempted. \
                 Fix the cause and re-run the same apply — completed steps replay as no-ops.",
                step.kind.label(),
                step.key
            );
            return Err(err);
        }
    }
    Ok(())
}

/// Resolve an [`EndpointRef`] to a concrete `endpoint_id`. `CreatedByName`
/// entries are filled in-process from the `add-endpoint` outcome of this
/// same run — the exact output-capture plumbing the manifest eliminates for
/// the operator.
fn resolve_endpoint_id(
    endpoint: &EndpointRef,
    created: &BTreeMap<String, String>,
) -> Result<String, OpError> {
    match endpoint {
        EndpointRef::Existing(id) => Ok(id.clone()),
        EndpointRef::CreatedByName(name) => created.get(name).cloned().ok_or_else(|| {
            OpError::InvalidArgument(format!(
                "internal: endpoint `{name}` was not created before its link step \
                 (add-endpoint outcome missing)"
            ))
        }),
    }
}

// --- verify ---------------------------------------------------------------------

/// Store-level post-conditions: re-read the environment and assert the
/// manifest's desired state is visible. Runtime readiness is the doctor's
/// job (PR-3), not apply's.
fn verify(store: &LocalFsStore, ctx: &ApplyContext) -> Result<Value, OpError> {
    let env = store.load(&ctx.env_id)?;
    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0usize;

    if let Some(url) = &ctx.canonical_public_base_url {
        checked += 1;
        if env.host_config.public_base_url.as_deref() != Some(url.as_str()) {
            failures.push(format!(
                "public_base_url is `{:?}`, expected `{url}`",
                env.host_config.public_base_url
            ));
        }
    }

    if ctx.manifest.trust_root == Some(TrustRootDirective::Bootstrap) {
        checked += 1;
        let env_dir = store.env_dir(&ctx.env_id)?;
        let trust_root = store_trust_root::load(&env_dir)?;
        match crate::operator_key::load_existing_only() {
            Ok(k)
                if trust_root
                    .keys
                    .iter()
                    .any(|t| t.key_id.eq_ignore_ascii_case(&k.key_id)) => {}
            Ok(k) => failures.push(format!(
                "operator key {} is not in the trust root",
                short_key_id(&k.key_id)
            )),
            Err(e) => failures.push(format!("operator key not loadable: {e}")),
        }
    }

    for (b, artifact) in ctx.manifest.bundles.iter().zip(&ctx.artifacts) {
        checked += 1;
        let Some(dep) = env
            .bundles
            .iter()
            .find(|d| d.bundle_id.as_str() == b.bundle_id && d.customer_id == artifact.customer_id)
        else {
            failures.push(format!("bundle `{}` is not deployed", b.bundle_id));
            continue;
        };
        if !deployment_converged(&env, dep.deployment_id, &artifact.digest) {
            failures.push(format!(
                "bundle `{}`: live revision digest is `{}`, expected `{}`",
                b.bundle_id,
                live_revision_digest(&env, dep.deployment_id).unwrap_or("none"),
                artifact.digest
            ));
        }
        if let Some(rb) = &b.route_binding {
            let desired = into_route_binding(rb.clone());
            if desired != dep.route_binding {
                failures.push(format!(
                    "bundle `{}`: route_binding differs from the manifest",
                    b.bundle_id
                ));
            }
        }
        if let Some(overrides) = &b.config_overrides
            && *overrides != dep.config_overrides
        {
            failures.push(format!(
                "bundle `{}`: config_overrides differ from the manifest",
                b.bundle_id
            ));
        }
    }

    for ep in &ctx.manifest.messaging_endpoints {
        checked += 1;
        let Some(m) = match_existing_endpoint(&env, ep)? else {
            failures.push(format!("endpoint `{}` is absent", ep.name));
            continue;
        };
        for link in &ep.links {
            if !m.linked_bundles.iter().any(|b| b.as_str() == *link) {
                failures.push(format!("endpoint `{}`: link `{link}` is absent", ep.name));
            }
        }
        if let Some(wf) = &ep.welcome_flow {
            let equal = m.welcome_flow.as_ref().is_some_and(|cur| {
                cur.bundle_id.as_str() == wf.bundle_id
                    && cur.pack_id.as_str() == wf.pack_id
                    && cur.flow_id == wf.flow_id
            });
            if !equal {
                failures.push(format!(
                    "endpoint `{}`: welcome_flow differs from the manifest",
                    ep.name
                ));
            }
        }
    }

    if failures.is_empty() {
        Ok(json!({ "checked": checked, "failures": [] }))
    } else {
        Err(OpError::Conflict(format!(
            "apply executed but post-verify found {} mismatch(es): {}",
            failures.len(),
            failures.join("; ")
        )))
    }
}

// --- helpers --------------------------------------------------------------------

/// Deterministic, replay-safe idempotency key:
/// `ulid(truncate_128(sha256(schema ‖ env ‖ kind ‖ natural_key ‖ desired_hash)))`.
/// Same manifest → same keys (a retry replays); changed desired state → new
/// keys (a real mutation). Rendered as a 26-char Crockford-base32 ULID so it
/// satisfies the `greentic-deploy-spec` `IdempotencyKey` shape.
fn derive_idempotency_key(
    env_id: &EnvId,
    step_kind: &str,
    natural_key: &str,
    desired_state_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    for part in [
        ENV_MANIFEST_SCHEMA_V1,
        env_id.as_str(),
        step_kind,
        natural_key,
        desired_state_hash,
    ] {
        hasher.update(part.as_bytes());
        hasher.update([0u8]);
    }
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    ulid::Ulid::from(u128::from_be_bytes(bytes)).to_string()
}

fn hash_json(value: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.to_string().as_bytes());
    hex::encode(hasher.finalize())
}

/// Digest of the revision currently carrying the (highest-weight) live
/// traffic for a deployment. `None` when the deployment has no split or the
/// split references an unknown revision.
fn live_revision_digest(env: &Environment, deployment_id: DeploymentId) -> Option<&str> {
    let split = env
        .traffic_splits
        .iter()
        .find(|s| s.deployment_id == deployment_id)?;
    let entry = split.entries.iter().max_by_key(|e| e.weight_bps)?;
    env.revisions
        .iter()
        .find(|r| r.revision_id == entry.revision_id)
        .map(|r| r.bundle_digest.as_str())
}

/// A digest the diff can trust: real `sha256:` material, not the
/// `sha256:00` placeholder pre-digest revisions carry.
fn digest_is_real(digest: &str) -> bool {
    digest.starts_with("sha256:") && digest.len() > "sha256:".len() && digest != "sha256:00"
}

/// Strict convergence: the deployment's traffic split has EXACTLY ONE entry
/// at full weight (10,000 bps), that entry's revision exists, carries a real
/// digest, and the digest matches `expected_digest`. A mixed split (e.g.
/// 60/40 blue-green) or a degenerate placeholder digest is NOT converged.
fn deployment_converged(
    env: &Environment,
    deployment_id: DeploymentId,
    expected_digest: &str,
) -> bool {
    let Some(split) = env
        .traffic_splits
        .iter()
        .find(|s| s.deployment_id == deployment_id)
    else {
        return false;
    };
    if split.entries.len() != 1 || split.entries[0].weight_bps != 10_000 {
        return false;
    }
    let entry = &split.entries[0];
    env.revisions
        .iter()
        .find(|r| r.revision_id == entry.revision_id)
        .is_some_and(|r| digest_is_real(&r.bundle_digest) && r.bundle_digest == expected_digest)
}

/// Re-hash the artifact at `path` and verify it still matches the digest
/// recorded at plan time. Returns `Err(Conflict)` if the bytes changed
/// between planning and execution (shrinks the TOCTOU window to what
/// `op deploy` itself has).
fn ensure_artifact_unchanged(path: &Path, expected: &str) -> Result<(), OpError> {
    let actual = super::bundle_stage::sha256_file(path).map_err(|source| OpError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if actual != expected {
        return Err(OpError::Conflict(format!(
            "artifact `{}` changed since the plan was computed (expected {}, found {}); \
             re-run apply",
            path.display(),
            short_digest(expected),
            short_digest(&actual),
        )));
    }
    Ok(())
}

fn short_digest(digest: &str) -> &str {
    let end = digest.len().min("sha256:".len() + 8);
    &digest[..end]
}

fn short_key_id(key_id: &str) -> &str {
    &key_id[..key_id.len().min(8)]
}

fn binding_summary(binding: &Option<RouteBinding>) -> String {
    match binding {
        None => "default binding".to_string(),
        Some(rb) => {
            let mut parts = Vec::new();
            if !rb.path_prefixes.is_empty() {
                parts.push(rb.path_prefixes.join(","));
            }
            if !rb.hosts.is_empty() {
                parts.push(format!("hosts={}", rb.hosts.join(",")));
            }
            parts.push(format!(
                "tenant={}/{}",
                rb.tenant_selector.tenant, rb.tenant_selector.team
            ));
            parts.join(" ")
        }
    }
}

fn render_plan(steps: &[ApplyStep], warnings: &[String]) {
    eprintln!("plan ({} step(s)):", steps.len());
    for step in steps {
        let action = match step.action {
            ApplyAction::Create => "create",
            ApplyAction::Update => "update",
            ApplyAction::NoOp => "no-op",
        };
        eprintln!(
            "  {:<22} {:<40} {:<7} {}",
            step.kind.label(),
            step.key,
            action,
            step.detail
        );
    }
    for w in warnings {
        eprintln!("  warning: {w}");
    }
}

fn report_json(
    ctx: &ApplyContext,
    steps: &[ApplyStep],
    mode: &str,
    verify: Option<Value>,
) -> Value {
    let changed = steps
        .iter()
        .filter(|s| s.action != ApplyAction::NoOp)
        .count();
    let mut report = json!({
        "manifest_schema": ENV_MANIFEST_SCHEMA_V1,
        "environment_id": ctx.env_id.as_str(),
        "mode": mode,
        "steps": steps.iter().map(ApplyStep::to_json).collect::<Vec<_>>(),
        "changed": changed,
        "no_op": steps.len() - changed,
        "warnings": ctx.warnings,
    });
    if let Some(v) = verify {
        report["verify"] = v;
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idempotency_keys_are_deterministic_and_state_sensitive() {
        let env_id = EnvId::try_from("local").unwrap();
        let a = derive_idempotency_key(&env_id, "add-endpoint", "realbot-legal", "h1");
        let b = derive_idempotency_key(&env_id, "add-endpoint", "realbot-legal", "h1");
        assert_eq!(a, b, "same inputs must derive the same key");
        assert_eq!(a.len(), 26, "ULID rendering is 26 chars");
        // Every input term must discriminate.
        let other_env = EnvId::try_from("prod").unwrap();
        assert_ne!(
            a,
            derive_idempotency_key(&other_env, "add-endpoint", "realbot-legal", "h1")
        );
        assert_ne!(
            a,
            derive_idempotency_key(&env_id, "link-endpoint", "realbot-legal", "h1")
        );
        assert_ne!(
            a,
            derive_idempotency_key(&env_id, "add-endpoint", "realbot-acct", "h1")
        );
        assert_ne!(
            a,
            derive_idempotency_key(&env_id, "add-endpoint", "realbot-legal", "h2")
        );
        // And the key must satisfy the spec shape.
        greentic_deploy_spec::IdempotencyKey::new(a).expect("derived key is spec-valid");
    }

    #[test]
    fn degenerate_digests_are_not_real() {
        assert!(!digest_is_real("sha256:00"));
        assert!(!digest_is_real("sha256:"));
        assert!(!digest_is_real(""));
        assert!(!digest_is_real("md5:abcd"));
        assert!(digest_is_real("sha256:ab12cd34"));
    }

    // --- LocalFsStore integration ---------------------------------------------

    use crate::cli::tests_common::{
        bootstrap_env_trust_root, make_bundle_deployment, make_env, make_revision,
        make_traffic_split,
    };
    use greentic_deploy_spec::RevisionLifecycle;
    use std::path::Path;
    use tempfile::tempdir;

    fn seeded_store() -> (tempfile::TempDir, LocalFsStore) {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        bootstrap_env_trust_root(&env_dir);
        (dir, store)
    }

    fn fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/bundles/perf-smoke-bundle.gtbundle")
    }

    fn write_manifest(dir: &Path, value: &Value) -> PathBuf {
        let path = dir.join("manifest.json");
        std::fs::write(&path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
        path
    }

    fn run_apply(store: &LocalFsStore, manifest_path: &Path) -> Result<OpOutcome, OpError> {
        let flags = OpFlags {
            schema_only: false,
            answers: Some(manifest_path.to_path_buf()),
        };
        apply(store, &flags, false, None, false)
    }

    fn run_dry(store: &LocalFsStore, manifest_path: &Path) -> Result<OpOutcome, OpError> {
        let flags = OpFlags {
            schema_only: false,
            answers: Some(manifest_path.to_path_buf()),
        };
        apply(store, &flags, true, None, false)
    }

    fn load_local(store: &LocalFsStore) -> Environment {
        store.load(&EnvId::try_from("local").unwrap()).unwrap()
    }

    /// The two-dept-shaped manifest: one bundle with a tenant-scoped path
    /// binding, one telegram endpoint linking it, plus a welcome flow.
    fn full_manifest(bundle_path: &Path) -> Value {
        json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{
                "bundle_id": "quickstart",
                "bundle_path": bundle_path,
                "route_binding": {
                    "path_prefixes": ["/legal"],
                    "tenant_selector": {"tenant": "legal", "team": "default"}
                }
            }],
            "messaging_endpoints": [{
                "name": "legal-bot",
                "provider_type": "messaging.telegram.bot",
                "links": ["quickstart"],
                "welcome_flow": {
                    "bundle_id": "quickstart",
                    "pack_id": "perf-smoke-pack",
                    "flow_id": "main"
                }
            }]
        })
    }

    fn step_actions(outcome: &Value) -> Vec<(String, String)> {
        outcome["steps"]
            .as_array()
            .expect("steps array")
            .iter()
            .map(|s| {
                (
                    s["kind"].as_str().unwrap().to_string(),
                    s["action"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn fresh_apply_then_noop_reapply() {
        let (dir, store) = seeded_store();
        let manifest_path = write_manifest(dir.path(), &full_manifest(&fixture()));

        let outcome = run_apply(&store, &manifest_path).expect("first apply succeeds");
        let result = outcome.result;
        assert_eq!(result["mode"], "apply");
        // deploy + add-endpoint + link + welcome-flow change; ensure-env no-ops.
        assert_eq!(result["changed"], 4, "result: {result}");
        assert_eq!(
            result["verify"]["failures"].as_array().unwrap().len(),
            0,
            "verify must pass: {result}"
        );

        let env = load_local(&store);
        assert_eq!(env.bundles.len(), 1);
        let dep = &env.bundles[0];
        assert_eq!(dep.route_binding.path_prefixes, vec!["/legal".to_string()]);
        assert_eq!(dep.route_binding.tenant_selector.tenant, "legal");
        let live = live_revision_digest(&env, dep.deployment_id).expect("live revision");
        assert_eq!(
            live,
            super::super::bundle_stage::sha256_file(&fixture()).unwrap(),
            "live revision must carry the artifact digest"
        );
        assert_eq!(env.messaging_endpoints.len(), 1);
        let ep = &env.messaging_endpoints[0];
        assert_eq!(ep.display_name, "legal-bot");
        assert_eq!(ep.provider_id, "legal-bot", "provider_id = manifest name");
        assert_eq!(
            ep.linked_bundles
                .iter()
                .map(|b| b.as_str())
                .collect::<Vec<_>>(),
            vec!["quickstart"]
        );
        let wf = ep.welcome_flow.as_ref().expect("welcome flow set");
        assert_eq!(wf.flow_id, "main");
        assert!(
            ep.webhook_secret_ref.is_some(),
            "telegram-class endpoint gets an auto-provisioned webhook secret"
        );

        // Unchanged re-apply: every step is a visible no-op, nothing re-staged.
        let revisions_before = env.revisions.len();
        let second = run_apply(&store, &manifest_path).expect("re-apply succeeds");
        assert_eq!(second.result["changed"], 0, "result: {}", second.result);
        let env = load_local(&store);
        assert_eq!(
            env.revisions.len(),
            revisions_before,
            "no-op re-apply must not stage a new revision"
        );
    }

    #[test]
    fn dry_run_mutates_nothing() {
        let (dir, store) = seeded_store();
        let manifest_path = write_manifest(dir.path(), &full_manifest(&fixture()));

        let outcome = run_dry(&store, &manifest_path).expect("dry-run succeeds");
        assert_eq!(outcome.result["mode"], "dry-run");
        assert_eq!(outcome.result["changed"], 4);
        assert!(
            outcome.result.get("verify").is_none(),
            "dry-run must not verify (nothing executed)"
        );

        let env = load_local(&store);
        assert!(env.bundles.is_empty(), "dry-run must not deploy");
        assert!(
            env.messaging_endpoints.is_empty(),
            "dry-run must not add endpoints"
        );
    }

    #[test]
    fn binding_only_change_plans_update_without_restage() {
        let (dir, store) = seeded_store();
        let manifest_path = write_manifest(dir.path(), &full_manifest(&fixture()));
        run_apply(&store, &manifest_path).expect("first apply");
        let revisions_before = load_local(&store).revisions.len();

        // Same artifact, different path prefix → exactly one update-bundle;
        // the deploy step must NOT appear (digest matches → no re-stage).
        let mut changed = full_manifest(&fixture());
        changed["bundles"][0]["route_binding"]["path_prefixes"] = json!(["/law"]);
        let manifest_path = write_manifest(dir.path(), &changed);

        let plan = run_dry(&store, &manifest_path).expect("dry-run");
        let actions = step_actions(&plan.result);
        assert!(
            actions.contains(&("update-bundle".to_string(), "update".to_string())),
            "plan: {actions:?}"
        );
        assert!(
            actions
                .iter()
                .all(|(kind, action)| kind != "deploy-bundle" || action == "no-op"),
            "digest match must not re-deploy: {actions:?}"
        );

        let outcome = run_apply(&store, &manifest_path).expect("apply binding change");
        assert_eq!(outcome.result["changed"], 1, "{}", outcome.result);
        let env = load_local(&store);
        assert_eq!(
            env.bundles[0].route_binding.path_prefixes,
            vec!["/law".to_string()]
        );
        assert_eq!(
            env.revisions.len(),
            revisions_before,
            "binding-only change must not stage a new revision"
        );
    }

    #[test]
    fn degenerate_live_digest_fails_toward_redeploy() {
        let (dir, store) = seeded_store();
        // Seed a pre-digest deployment by hand: live revision carries the
        // `sha256:00` placeholder.
        let mut env = make_env("local");
        let dep = make_bundle_deployment("local", "quickstart");
        let rev = make_revision(
            "local",
            "quickstart",
            &dep.deployment_id,
            1,
            RevisionLifecycle::Ready,
        );
        env.traffic_splits.push(make_traffic_split(
            "local",
            "quickstart",
            &dep.deployment_id,
            &rev.revision_id,
            "seed",
        ));
        env.bundles.push(dep);
        env.revisions.push(rev);
        store.save(&env).unwrap();

        // No route_binding in the manifest → the only pending step must be
        // the re-deploy (unknown digest fails toward deploy, never toward skip).
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{"bundle_id": "quickstart", "bundle_path": fixture()}]
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        let plan = run_dry(&store, &manifest_path).expect("dry-run");
        let actions = step_actions(&plan.result);
        assert!(
            actions.contains(&("deploy-bundle".to_string(), "update".to_string())),
            "degenerate digest must plan a re-deploy: {actions:?}"
        );
        assert_eq!(plan.result["changed"], 1, "{}", plan.result);
    }

    #[test]
    fn endpoint_ambiguity_is_an_error() {
        let (dir, store) = seeded_store();
        // Two endpoints with the same (provider_type, display_name) pair but
        // distinct provider_ids — legal at the store level, ambiguous for the
        // manifest's natural key.
        for provider_id in ["bot-a", "bot-b"] {
            super::super::messaging::add(
                &store,
                &OpFlags::default(),
                Some(EndpointAddPayload {
                    environment_id: "local".to_string(),
                    provider_id: provider_id.to_string(),
                    provider_type: "messaging.telegram.bot".to_string(),
                    display_name: "legal-bot".to_string(),
                    secret_refs: Vec::new(),
                    idempotency_key: None,
                    updated_by: "test".to_string(),
                }),
            )
            .expect("seed endpoint");
        }
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "messaging_endpoints": [
                {"name": "legal-bot", "provider_type": "messaging.telegram.bot"}
            ]
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        let err = run_apply(&store, &manifest_path).unwrap_err();
        match err {
            OpError::Conflict(msg) => {
                assert!(msg.contains("refuses to guess"), "got: {msg}")
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn provider_type_mismatch_on_matched_name_is_an_error() {
        let (dir, store) = seeded_store();
        super::super::messaging::add(
            &store,
            &OpFlags::default(),
            Some(EndpointAddPayload {
                environment_id: "local".to_string(),
                provider_id: "legal-bot".to_string(),
                provider_type: "messaging.teams.bot".to_string(),
                display_name: "legal-bot".to_string(),
                secret_refs: Vec::new(),
                idempotency_key: None,
                updated_by: "test".to_string(),
            }),
        )
        .expect("seed endpoint");
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "messaging_endpoints": [
                {"name": "legal-bot", "provider_type": "messaging.telegram.bot"}
            ]
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        let err = run_apply(&store, &manifest_path).unwrap_err();
        match err {
            OpError::Conflict(msg) => assert!(msg.contains("repurpose"), "got: {msg}"),
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn link_to_unknown_bundle_is_an_error() {
        let (dir, store) = seeded_store();
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "messaging_endpoints": [{
                "name": "legal-bot",
                "provider_type": "messaging.telegram.bot",
                "links": ["ghost"]
            }]
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        let err = run_apply(&store, &manifest_path).unwrap_err();
        match err {
            OpError::InvalidArgument(msg) => assert!(msg.contains("ghost"), "got: {msg}"),
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
        // Validation failures must not mutate anything.
        assert!(load_local(&store).messaging_endpoints.is_empty());
    }

    #[test]
    fn partial_failure_resumes_on_reapply() {
        let (dir, store) = seeded_store();
        // Second bundle's artifact is garbage — validation passes (it IS a
        // file with a digest), execution fails at the stage step.
        let broken = dir.path().join("broken.gtbundle");
        std::fs::write(&broken, b"not a squashfs").unwrap();
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [
                {"bundle_id": "quickstart", "bundle_path": fixture()},
                {"bundle_id": "broken", "bundle_path": broken}
            ]
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        run_apply(&store, &manifest_path).expect_err("garbage artifact must fail the apply");

        // Fail-fast left the store valid — the store is the checkpoint. The
        // first bundle is fully routed; the broken one failed at the stage
        // step AFTER its `bundles add` landed, so its deployment record
        // exists but carries no live traffic split.
        let env = load_local(&store);
        assert_eq!(env.bundles.len(), 2, "both deployment records exist");
        assert_eq!(
            env.traffic_splits.len(),
            1,
            "only the first bundle is routed"
        );
        assert_eq!(
            env.traffic_splits[0].bundle_id.as_str(),
            "quickstart",
            "the routed split belongs to the bundle that staged successfully"
        );

        // Fix the manifest (point `broken` at the real artifact) and re-run:
        // the completed bundle no-ops, only the remainder executes.
        let fixed = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [
                {"bundle_id": "quickstart", "bundle_path": fixture()},
                {"bundle_id": "broken", "bundle_path": fixture()}
            ]
        });
        let manifest_path = write_manifest(dir.path(), &fixed);
        let outcome = run_apply(&store, &manifest_path).expect("resume succeeds");
        assert_eq!(outcome.result["changed"], 1, "{}", outcome.result);
        let env = load_local(&store);
        assert_eq!(env.bundles.len(), 2);
    }

    #[test]
    fn missing_nonlocal_env_is_rejected() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "prod"}
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        let err = run_apply(&store, &manifest_path).unwrap_err();
        match err {
            OpError::NotFound(msg) => {
                assert!(msg.contains("bootstraps only"), "got: {msg}")
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn link_satisfied_only_by_env_warns() {
        let (dir, store) = seeded_store();
        // Deploy a bundle imperatively, then link to it from a manifest that
        // does not declare it: a warning, not an error (layered manifests).
        super::super::deploy::deploy(
            &store,
            &OpFlags::default(),
            Some(BundleDeployPayload {
                environment_id: "local".to_string(),
                bundle_id: "preexisting".to_string(),
                customer_id: None,
                bundle_path: Some(fixture()),
                idempotency_key: None,
                config_overrides: None,
                route_binding: None,
            }),
        )
        .expect("imperative deploy");
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "messaging_endpoints": [{
                "name": "legal-bot",
                "provider_type": "messaging.telegram.bot",
                "links": ["preexisting"]
            }]
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        let outcome = run_apply(&store, &manifest_path).expect("apply succeeds with warning");
        let warnings = outcome.result["warnings"].as_array().unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.as_str().unwrap().contains("pre-existing")),
            "warnings: {warnings:?}"
        );
        let env = load_local(&store);
        assert_eq!(env.messaging_endpoints[0].linked_bundles.len(), 1);
    }

    // --- Fix 1: customer-aware bundle matching ---

    #[test]
    fn cross_customer_deployment_is_rejected() {
        let (dir, store) = seeded_store();
        // Seed a deployment owned by "other-customer".
        let mut env = make_env("local");
        let mut dep = make_bundle_deployment("local", "quickstart");
        dep.customer_id = CustomerId::new("other-customer");
        env.bundles.push(dep);
        store.save(&env).unwrap();

        // Manifest declares the same bundle_id but resolves to the default
        // customer "local-dev" → Conflict.
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{"bundle_id": "quickstart", "bundle_path": fixture()}]
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        let err = run_apply(&store, &manifest_path).unwrap_err();
        match err {
            OpError::Conflict(msg) => {
                assert!(msg.contains("other-customer"), "got: {msg}");
                assert!(msg.contains("local-dev"), "got: {msg}");
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
        // No mutation.
        let env = load_local(&store);
        assert!(env.revisions.is_empty());
    }

    // --- Fix 2: pre-deploy artifact re-hash ---

    #[test]
    fn ensure_artifact_unchanged_catches_modification() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.bin");
        std::fs::write(&path, b"original content").unwrap();
        let digest = super::super::bundle_stage::sha256_file(&path).unwrap();

        // Same bytes → Ok.
        ensure_artifact_unchanged(&path, &digest).expect("unchanged file must pass");

        // Mutate → Err(Conflict).
        std::fs::write(&path, b"tampered content").unwrap();
        let err = ensure_artifact_unchanged(&path, &digest).unwrap_err();
        match err {
            OpError::Conflict(msg) => {
                assert!(msg.contains("changed since the plan"), "got: {msg}")
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    // --- Fix 3: strict convergence check ---

    #[test]
    fn mixed_split_is_not_converged_plans_redeploy() {
        use greentic_deploy_spec::TrafficSplitEntry;

        let (dir, store) = seeded_store();
        let real_digest = super::super::bundle_stage::sha256_file(&fixture()).unwrap();

        let mut env = make_env("local");
        let dep = make_bundle_deployment("local", "quickstart");
        let mut rev1 = make_revision(
            "local",
            "quickstart",
            &dep.deployment_id,
            1,
            RevisionLifecycle::Ready,
        );
        rev1.bundle_digest = real_digest;
        let rev2 = make_revision(
            "local",
            "quickstart",
            &dep.deployment_id,
            2,
            RevisionLifecycle::Ready,
        );
        // Two-entry split: 6000/4000 — sum = 10_000 (valid).
        let mut split = make_traffic_split(
            "local",
            "quickstart",
            &dep.deployment_id,
            &rev1.revision_id,
            "seed",
        );
        split.entries[0].weight_bps = 6_000;
        split.entries.push(TrafficSplitEntry {
            revision_id: rev2.revision_id,
            weight_bps: 4_000,
        });
        env.bundles.push(dep);
        env.revisions.push(rev1);
        env.revisions.push(rev2);
        env.traffic_splits.push(split);
        store.save(&env).unwrap();

        // Manifest: same bundle, same artifact (top entry digest matches) —
        // but the split is mixed, so it MUST plan a re-deploy, not a no-op.
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{"bundle_id": "quickstart", "bundle_path": fixture()}]
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        let plan = run_dry(&store, &manifest_path).expect("dry-run");
        let actions = step_actions(&plan.result);
        assert!(
            actions.contains(&("deploy-bundle".to_string(), "update".to_string())),
            "mixed split must plan a re-deploy: {actions:?}"
        );
        assert!(plan.result["changed"].as_u64().unwrap() >= 1);
    }

    // --- Fix 4: deploy BEFORE binding update ---

    #[test]
    fn deploy_precedes_binding_update_when_both_differ() {
        let (dir, store) = seeded_store();
        // Seed: deployment with degenerate digest (needs deploy) + binding
        // that differs from the manifest's.
        let mut env = make_env("local");
        let dep = make_bundle_deployment("local", "quickstart");
        let rev = make_revision(
            "local",
            "quickstart",
            &dep.deployment_id,
            1,
            RevisionLifecycle::Ready,
        );
        env.traffic_splits.push(make_traffic_split(
            "local",
            "quickstart",
            &dep.deployment_id,
            &rev.revision_id,
            "seed",
        ));
        env.bundles.push(dep);
        env.revisions.push(rev);
        store.save(&env).unwrap();

        // Manifest with the fixture path AND a different binding (/legal).
        let manifest = full_manifest(&fixture());
        let manifest_path = write_manifest(dir.path(), &manifest);
        let plan = run_dry(&store, &manifest_path).expect("dry-run");
        let steps = plan.result["steps"].as_array().expect("steps");

        // Find indices of deploy-bundle (update) and update-bundle (update).
        let deploy_idx = steps
            .iter()
            .position(|s| s["kind"] == "deploy-bundle" && s["action"] == "update")
            .expect("deploy-bundle update step");
        let update_idx = steps
            .iter()
            .position(|s| s["kind"] == "update-bundle" && s["action"] == "update")
            .expect("update-bundle update step");

        assert!(
            deploy_idx < update_idx,
            "deploy-bundle (idx {deploy_idx}) must precede update-bundle (idx {update_idx}): \
             {steps:?}"
        );
    }
}
