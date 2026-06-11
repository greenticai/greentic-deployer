//! `gtc op env apply` — declarative, upsert-only environment apply
//! (PR-1 + PR-2 of `plans/env-manifest-apply.md`).
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
//!   compatible). Exceptions: `deploy`'s traffic cut-over key intentionally
//!   stays per-revision-derived (a re-stage is by definition a new
//!   cut-over); `put-secret` carries no deterministic key (an always-put is
//!   by definition a new write — a value-insensitive key would conflate
//!   rotations in audit and break A8 same-key-different-body semantics;
//!   `secrets::put` mints a fresh per-invocation key).
//! - Store-level verify only: *runtime* readiness (secrets resolvable by
//!   the reader, routes served) is `gtc doctor`'s job — apply must work
//!   without a running runtime.
//! - `--check` (CI convergence gate): validate + diff + plan, never
//!   mutate; exit non-zero when diffable changes are pending. Always-put
//!   secret rows are excluded from the verdict (values cannot be diffed
//!   until A9) and reported under `undiffable` instead.
//! - Missing-inputs contract: an unset `from_env` variable or an absent
//!   `bundle_path` artifact is *collected* (not fail-fast) and reported
//!   under `missing` in the JSON report, so one run surfaces every gap.
//!   Mutating apply refuses to execute while any remain; on a TTY, missing
//!   secret values are prompted for (masked, in-memory only).
//!   `--non-interactive` never prompts and implies `--yes`; `--dry-run` and
//!   `--check` report missing inputs without failing on them (`--check`
//!   excludes them from the convergence verdict — CI gates must be runnable
//!   without holding credentials). `--emit-answers-template <path>` writes
//!   a skeleton manifest to start from.
//!
//! - Secrets are always-put: `op secrets get` is not-yet-implemented, so
//!   values cannot be diffed — the plan says `put (cannot diff)` instead of
//!   ever claiming a false no-op. Values resolve from `from_env` process
//!   variables at validation time and never appear in the manifest, plan,
//!   report, or audit records.
//!
//! Every mutation is executed through the existing single-purpose verb
//! functions (`deploy::deploy`, `bundles::update`, `messaging::add`/…,
//! `secrets::put`, `trust_root::bootstrap`, `env::init`/`set_public_url`),
//! so audit, authorization, signing, and revenue-policy logic stay
//! single-sourced — each step lands its own audit event under the composed
//! verb's noun.
//!
//! Human-readable plan/progress lines go to **stderr**; stdout carries only
//! the standard `{op, noun, result}` JSON envelope (so the output is
//! already machine-readable — no separate `--json` flag).

use std::collections::{BTreeMap, BTreeSet};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use greentic_deploy_spec::{
    CustomerId, DeploymentId, EnvId, Environment, MessagingEndpoint, RouteBinding,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::environment::{EnvironmentStore, LocalFsStore, trust_root as store_trust_root};
use crate::runtime_secrets::SecretValue;

use super::bundles::{BundleUpdatePayload, RouteBindingPayload, into_route_binding};
use super::deploy::BundleDeployPayload;
use super::env::EnvInitPayload;
use super::env_manifest::{
    ENV_MANIFEST_SCHEMA_V1, EnvManifest, ManifestBundle, ManifestEndpoint, ManifestWelcomeFlow,
    TrustRootDirective, manifest_schema,
};
use super::messaging::{
    EndpointAddPayload, EndpointLinkBundlePayload, EndpointSetWelcomeFlowPayload, EndpointSummary,
};
use super::secrets::SecretsPutPayload;
use super::trust_root::TrustRootBootstrapPayload;
use super::{OpError, OpFlags, OpOutcome};

const NOUN: &str = "env";
const VERB: &str = "apply";

/// Audit principal stamped on every composed mutation when the caller
/// doesn't pass `--updated-by`.
const DEFAULT_UPDATED_BY: &str = "env-apply";

// --- plan model ---------------------------------------------------------------

/// What the diff decided for one step. `Put` is the secrets-only
/// "cannot diff, write unconditionally" action (`op secrets get` is
/// not-yet-implemented for every backend, so a no-op can never be claimed);
/// warning-carrying no-ops surface through the plan's `warnings` list
/// instead of a dedicated `Skip` action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApplyAction {
    Create,
    Update,
    Put,
    NoOp,
}

impl ApplyAction {
    fn as_str(self) -> &'static str {
        match self {
            ApplyAction::Create => "create",
            ApplyAction::Update => "update",
            ApplyAction::Put => "put",
            ApplyAction::NoOp => "no-op",
        }
    }

    /// Does this action represent *diffable* drift for the `--check`
    /// convergence verdict? `Put` is excluded: always-put secret rows are
    /// unknowable until A9 lands a real `secrets get`, so counting them
    /// would make `--check` permanently red for any manifest with a
    /// `secrets[]` section. They stay visible in the report (`put` rows
    /// plus the `undiffable` count) instead of failing the gate.
    fn counts_as_drift(self) -> bool {
        matches!(self, ApplyAction::Create | ApplyAction::Update)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApplyStepKind {
    EnsureEnvironment,
    BootstrapTrustRoot,
    PutSecret,
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
            ApplyStepKind::PutSecret => "put-secret",
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
    /// The resolved VALUE deliberately does not live in the step (steps
    /// derive `Debug` and serialize into the plan/report) — execute looks it
    /// up in [`ApplyContext::secret_values`] by this path.
    PutSecret {
        path: String,
    },
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
    },
    WelcomeFlow {
        endpoint: EndpointRef,
        flow: ManifestWelcomeFlow,
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
            "action": self.action.as_str(),
            "detail": self.detail,
            "idempotency_key": self.idempotency_key,
        })
    }
}

// --- validated context ---------------------------------------------------------

/// A manifest bundle entry paired with its resolved artifact metadata.
struct ResolvedBundle {
    spec: ManifestBundle,
    resolved_path: PathBuf,
    digest: String,
    /// Billing principal resolved during validation (from
    /// `resolve_customer_id`). Used to match deployments by the same
    /// `(bundle_id, customer_id)` pair that `op deploy` keys on.
    customer_id: CustomerId,
}

/// A manifest endpoint entry paired with its store match (if any).
struct ResolvedEndpoint {
    spec: ManifestEndpoint,
    /// Cloned from the store — `None` when the endpoint is new.
    matched: Option<MessagingEndpoint>,
}

/// Everything validation established, handed to diff/execute/verify.
struct ApplyContext {
    env_id: EnvId,
    manifest: EnvManifest,
    /// Secret values keyed by the manifest's verbatim `path`, resolved from
    /// `from_env` during validation. Never serialized; [`SecretValue`]'s
    /// `Debug` renders a fixed placeholder, so no derived-`Debug` surface
    /// can echo the material — the value reaches exactly one place, the
    /// `secrets::put` payload at execute time.
    secret_values: BTreeMap<String, SecretValue>,
    /// Secret paths whose value came from the TTY prompter rather than the
    /// named env var — the plan row says `prompted` instead of `from $VAR`.
    prompted_paths: BTreeSet<String>,
    bundles: Vec<ResolvedBundle>,
    endpoints: Vec<ResolvedEndpoint>,
    env: Option<Environment>,
    /// Canonicalized `environment.public_base_url` (validated form).
    canonical_public_base_url: Option<String>,
    /// Accumulated input gaps (see [`MissingItem`]): secrets in manifest
    /// order, then bundles in manifest order.
    missing: Vec<MissingItem>,
    warnings: Vec<String>,
    updated_by: String,
}

// --- entry point ----------------------------------------------------------------

/// An input the manifest names but the process cannot supply: an unset
/// (or empty) `from_env` variable, or a `bundle_path` that is not a file.
/// Missing inputs are *accumulated* during validation (unlike structural
/// manifest errors, which stay fail-fast) so headless callers see the
/// complete list in one run, and reported under `missing` in the JSON
/// report. Apply mode refuses to execute while any remain; preview modes
/// (`--dry-run`, `--check`) report them without failing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MissingItem {
    kind: MissingKind,
    /// Natural key: the secret's manifest `path`, or the bundle's
    /// `bundle_id`.
    key: String,
    /// Where the input was expected: `env:<VAR>` or `path:<resolved path>`.
    source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MissingKind {
    SecretValue,
    BundleArtifact,
}

impl MissingKind {
    fn as_str(self) -> &'static str {
        match self {
            MissingKind::SecretValue => "secret_value",
            MissingKind::BundleArtifact => "bundle_artifact",
        }
    }
}

impl MissingItem {
    fn to_json(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "key": self.key,
            "source": self.source,
        })
    }
}

/// How `apply` terminates once the plan is computed.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ApplyMode {
    /// Execute the plan and verify (the default).
    #[default]
    Apply,
    /// Print the plan and exit 0 without mutating — a preview, even when
    /// changes are pending.
    DryRun,
    /// CI convergence gate: print the plan, never mutate, and fail
    /// (non-zero exit) when diffable changes are pending. Always-put
    /// secret rows don't count as drift ([`ApplyAction::counts_as_drift`]).
    Check,
}

impl ApplyMode {
    fn as_str(self) -> &'static str {
        match self {
            ApplyMode::Apply => "apply",
            ApplyMode::DryRun => "dry-run",
            ApplyMode::Check => "check",
        }
    }
}

/// Knobs for [`apply`] beyond the global `OpFlags`. Built from
/// `EnvApplyArgs` on the CLI path; library callers (greentic-setup's env
/// mode) construct it directly — `Default` is a plain mutating apply.
#[derive(Debug, Clone, Default)]
pub struct ApplyOptions {
    pub mode: ApplyMode,
    /// Audit principal forwarded to every composed mutation. Defaults to
    /// `env-apply`.
    pub updated_by: Option<String>,
    /// Skip the interactive plan confirmation.
    pub yes: bool,
    /// Never prompt — neither for missing secret values nor the plan
    /// confirmation (implies `yes`). Missing inputs are collected and
    /// reported instead of asked for.
    pub non_interactive: bool,
    /// Write a skeleton manifest to this path and exit — no `--answers`,
    /// no store access.
    pub emit_answers_template: Option<PathBuf>,
}

/// `gtc op env apply --answers <manifest.json> [--dry-run | --check |
/// --non-interactive] [--emit-answers-template <path>] [--updated-by <who>]
/// [--yes]`.
pub fn apply(
    store: &LocalFsStore,
    flags: &OpFlags,
    opts: ApplyOptions,
) -> Result<OpOutcome, OpError> {
    // TTY fill-in is offered only when the run could actually mutate
    // (prompting during a preview is noise) and the operator can answer.
    // rpassword prompts and reads on /dev/tty directly, so a redirected
    // stdout never sees the prompt and the JSON envelope stays clean.
    let interactive = opts.mode == ApplyMode::Apply
        && !opts.non_interactive
        && std::io::stdin().is_terminal()
        && std::io::stderr().is_terminal();
    let prompter: Option<&SecretPrompter> = if interactive {
        Some(&prompt_secret_value)
    } else {
        None
    };
    apply_with_lookups(
        store,
        flags,
        opts,
        &|name| std::env::var(name).ok(),
        prompter,
    )
}

/// Fallback asked for a secret value when the manifest's `from_env`
/// variable is unset: `(manifest path, from_env name) -> value`. `None`
/// means "still missing" — the path lands in the missing-inputs report.
type SecretPrompter = dyn Fn(&str, &str) -> Option<String>;

/// Masked TTY prompt for one missing secret value. Empty input declines —
/// the path stays missing and apply aborts with the full report. The value
/// lives only in the in-memory [`SecretValue`] map, exactly like an
/// env-resolved one; it never reaches the manifest, plan, report, or audit.
fn prompt_secret_value(path: &str, from_env: &str) -> Option<String> {
    let value = rpassword::prompt_password(format!(
        "secret `{path}`: ${from_env} is unset — enter value (hidden; empty to abort): "
    ))
    .ok()?;
    (!value.is_empty()).then_some(value)
}

/// [`apply`] with the `from_env` secret-value lookup and the TTY prompter
/// injected. Tests pass fakes so they never mutate the process environment
/// (`set_var` is unsafe under a multithreaded test harness) and never need
/// a TTY.
fn apply_with_lookups(
    store: &LocalFsStore,
    flags: &OpFlags,
    opts: ApplyOptions,
    env_lookup: &dyn Fn(&str) -> Option<String>,
    prompter: Option<&SecretPrompter>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, VERB, manifest_schema()));
    }
    if let Some(path) = &opts.emit_answers_template {
        std::fs::write(path, super::env_manifest::MANIFEST_TEMPLATE_JSON).map_err(|source| {
            OpError::Io {
                path: path.clone(),
                source,
            }
        })?;
        return Ok(OpOutcome::new(
            NOUN,
            VERB,
            json!({
                "manifest_schema": ENV_MANIFEST_SCHEMA_V1,
                "mode": "emit-answers-template",
                "path": path,
            }),
        ));
    }
    let ApplyOptions {
        mode,
        updated_by,
        yes,
        non_interactive,
        emit_answers_template: _,
    } = opts;
    let yes = yes || non_interactive;
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

    let ctx = resolve_and_validate(
        store,
        manifest,
        &manifest_dir,
        updated_by,
        env_lookup,
        prompter,
    )?;
    let steps = diff(store, &ctx)?;
    render_plan(&steps, &ctx.warnings, &ctx.missing);

    match mode {
        ApplyMode::DryRun => {
            return Ok(OpOutcome::new(
                NOUN,
                VERB,
                report_json(&ctx, &steps, mode.as_str(), None),
            ));
        }
        ApplyMode::Check => {
            // Missing inputs are reported but deliberately NOT drift: a CI
            // convergence gate must be runnable without holding the secret
            // values themselves (they're excluded from the verdict as
            // undiffable anyway). Mutating apply still requires them below.
            let diffable_pending = steps.iter().filter(|s| s.action.counts_as_drift()).count();
            if diffable_pending > 0 {
                return Err(OpError::Conflict(format!(
                    "env `{}` is not converged: {diffable_pending} pending change(s) — \
                     run `gtc op env apply --answers <manifest>` to reconcile (see the \
                     plan above for the step list)",
                    ctx.env_id.as_str()
                )));
            }
            return Ok(OpOutcome::new(
                NOUN,
                VERB,
                report_json(&ctx, &steps, mode.as_str(), None),
            ));
        }
        ApplyMode::Apply => {}
    }

    // Mutating apply refuses to run while any input is missing — the plan
    // above already lists every gap (the whole point of accumulating them),
    // so the operator fixes all of them in one round trip.
    if !ctx.missing.is_empty() {
        return Err(OpError::InvalidArgument(format!(
            "cannot apply: {} missing input(s): {} — export the named variable(s) / \
             provide the artifact(s) and re-run (on a TTY, missing secret values are \
             prompted for)",
            ctx.missing.len(),
            ctx.missing
                .iter()
                .map(|m| format!("{} `{}` ({})", m.kind.as_str(), m.key, m.source))
                .collect::<Vec<_>>()
                .join(", "),
        )));
    }

    let pending = steps
        .iter()
        .filter(|s| s.action != ApplyAction::NoOp)
        .count();
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
    env_lookup: &dyn Fn(&str) -> Option<String>,
    prompter: Option<&SecretPrompter>,
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

    // Secrets: resolve every `from_env` (set + non-empty) and pre-check the
    // bound secrets backend, all before any mutation. Values land ONLY in
    // `secret_values` (never in steps, plan, report, or audit targets).
    // Path canonicality was already checked by `validate_shape`.
    // Backend pre-check applies only when the env already exists — a fresh
    // env is exempt because the `env init` step creates the default
    // dev-store binding before any put-secret step runs.
    if !manifest.secrets.is_empty()
        && let Some(env) = &env
    {
        let secrets_pack = super::secrets::require_secrets_pack(env, &env_id)?;
        if secrets_pack.kind.path() != super::secrets::DEV_STORE_KIND_PATH {
            return Err(OpError::NotYetImplemented(format!(
                "manifest secrets[] write through the dev-store only; env `{env_id}` \
                 binds `{}` — backend dispatch beyond the dev-store lands in A9 \
                 (env-pack registry)",
                secrets_pack.kind
            )));
        }
    }
    // An unresolvable value is a MISSING INPUT, not a structural error:
    // collect every gap (offering the TTY prompter as a fallback) instead
    // of failing on the first, so one run reports the complete list.
    let mut missing = Vec::new();
    let mut secret_values = BTreeMap::new();
    let mut prompted_paths = BTreeSet::new();
    for s in &manifest.secrets {
        let env_value = env_lookup(&s.from_env).filter(|v| !v.is_empty());
        let value = match env_value {
            Some(v) => Some(v),
            None => prompter.and_then(|p| {
                let v = p(&s.path, &s.from_env).filter(|v| !v.is_empty());
                if v.is_some() {
                    prompted_paths.insert(s.path.clone());
                }
                v
            }),
        };
        match value {
            Some(v) => {
                secret_values.insert(s.path.clone(), SecretValue::from(v));
            }
            None => missing.push(MissingItem {
                kind: MissingKind::SecretValue,
                key: s.path.clone(),
                source: format!("env:{}", s.from_env),
            }),
        }
    }

    // Bundle artifacts: existence + digest, plus the B10 billing-principal
    // rule, all before any mutation. The principal rule stays fail-fast
    // (a manifest bug); an absent artifact is a missing input — the bundle
    // is reported and skipped (no digest means nothing to diff against).
    let mut resolved_bundles = Vec::with_capacity(manifest.bundles.len());
    for b in &manifest.bundles {
        let customer_id = super::bundles::resolve_customer_id(&env_id, b.customer_id.clone())?;
        let resolved_path = if b.bundle_path.is_absolute() {
            b.bundle_path.clone()
        } else {
            manifest_dir.join(&b.bundle_path)
        };
        if !resolved_path.is_file() {
            missing.push(MissingItem {
                kind: MissingKind::BundleArtifact,
                key: b.bundle_id.clone(),
                source: format!("path:{}", resolved_path.display()),
            });
            continue;
        }
        let digest =
            super::bundle_stage::sha256_file(&resolved_path).map_err(|source| OpError::Io {
                path: resolved_path.clone(),
                source,
            })?;
        resolved_bundles.push(ResolvedBundle {
            spec: b.clone(),
            resolved_path,
            digest,
            customer_id,
        });
    }

    // Deployment natural-key sanity: `op deploy` keys on
    // `(bundle_id, customer_id)`. Refuse to adopt a deployment owned by a
    // different billing principal, and reject same-pair ambiguity.
    if let Some(env) = &env {
        for rb in &resolved_bundles {
            let same_customer: Vec<_> = env
                .bundles
                .iter()
                .filter(|d| {
                    d.bundle_id.as_str() == rb.spec.bundle_id && d.customer_id == rb.customer_id
                })
                .collect();
            let other_customer: Vec<_> = env
                .bundles
                .iter()
                .filter(|d| {
                    d.bundle_id.as_str() == rb.spec.bundle_id && d.customer_id != rb.customer_id
                })
                .collect();
            if !other_customer.is_empty() {
                return Err(OpError::Conflict(format!(
                    "bundle `{}`: deployment owned by customer `{}` exists but manifest \
                     resolves to `{}` — apply refuses to adopt a deployment owned by a \
                     different customer",
                    rb.spec.bundle_id,
                    other_customer[0].customer_id.as_str(),
                    rb.customer_id.as_str(),
                )));
            }
            if same_customer.len() > 1 {
                return Err(OpError::Conflict(format!(
                    "bundle `{}` matches {} deployments for customer `{}` in env `{env_id}` \
                     — apply refuses to guess; reconcile with `gtc op bundles list {env_id}` \
                     first",
                    rb.spec.bundle_id,
                    same_customer.len(),
                    rb.customer_id.as_str(),
                )));
            }
        }
    }

    let mut warnings = Vec::new();

    // Endpoint link targets + match ambiguity + welcome-flow reachability.
    let mut resolved_endpoints = Vec::with_capacity(manifest.messaging_endpoints.len());
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
        resolved_endpoints.push(ResolvedEndpoint {
            spec: ep.clone(),
            matched: matched.cloned(),
        });
    }

    Ok(ApplyContext {
        env_id,
        manifest,
        secret_values,
        prompted_paths,
        bundles: resolved_bundles,
        endpoints: resolved_endpoints,
        env,
        canonical_public_base_url,
        missing,
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

    // 3. Secrets — always-put: `op secrets get` is not-yet-implemented for
    //    every backend, so values cannot be diffed. The plan says so
    //    explicitly rather than ever claiming a false no-op; when A9 lands a
    //    real `get`, this tightens to write-if-changed with no schema
    //    change. Secrets land before bundles so a just-deployed revision
    //    never serves a request that resolves a missing secret.
    for s in &ctx.manifest.secrets {
        // Deliberately NO deterministic idempotency key: an always-put is
        // by definition a NEW write (values cannot be diffed until A9), so
        // a value-insensitive key would stamp two semantically different
        // writes (e.g. a secret rotation under the same env var) with the
        // same key — conflating audit records and wrongly replaying under
        // any future same-key dedupe layer (A8 same-key-different-body
        // conflict rule). `secrets::put` mints a fresh per-invocation key
        // instead (second exception alongside deploy's per-revision
        // cut-over key).
        let detail = if ctx.prompted_paths.contains(&s.path) {
            "prompted (cannot diff until A9)".to_string()
        } else {
            format!("from ${} (cannot diff until A9)", s.from_env)
        };
        steps.push(ApplyStep {
            kind: ApplyStepKind::PutSecret,
            key: s.path.clone(),
            action: ApplyAction::Put,
            detail,
            idempotency_key: None,
            op: StepOp::PutSecret {
                path: s.path.clone(),
            },
        });
    }

    // 4. Bundles (keyed on `(bundle_id, customer_id)` — the same natural key
    //    that `op deploy` uses).
    for rb in &ctx.bundles {
        let existing = ctx.env.as_ref().and_then(|e| {
            e.bundles.iter().find(|d| {
                d.bundle_id.as_str() == rb.spec.bundle_id && d.customer_id == rb.customer_id
            })
        });
        match existing {
            None => {
                let detail = format!(
                    "{} → {}",
                    short_digest(&rb.digest),
                    binding_summary(&rb.spec.route_binding.clone().map(into_route_binding))
                );
                steps.push(ApplyStep {
                    kind: ApplyStepKind::DeployBundle,
                    key: rb.spec.bundle_id.clone(),
                    action: ApplyAction::Create,
                    detail,
                    idempotency_key: None, // deploy derives its cut-over key per revision
                    op: StepOp::Deploy {
                        payload: Box::new(deploy_payload(
                            &env_id_str,
                            rb,
                            rb.spec.route_binding.clone(),
                        )),
                        expected_digest: rb.digest.clone(),
                    },
                });
            }
            Some(dep) => {
                let desired_binding: Option<RouteBinding> =
                    rb.spec.route_binding.clone().map(into_route_binding);
                let binding_differs = desired_binding
                    .as_ref()
                    .is_some_and(|b| *b != dep.route_binding);
                let overrides_differ = rb
                    .spec
                    .config_overrides
                    .as_ref()
                    .is_some_and(|o| *o != dep.config_overrides);
                let env = ctx.env.as_ref().expect("existing deployment implies env");
                let converged = deployment_converged(env, dep.deployment_id, &rb.digest);
                let needs_deploy = !converged;
                let live = live_revision_digest(env, dep.deployment_id);

                // Deploy FIRST when re-staging is needed (routing-metadata-
                // last: a stage failure leaves the OLD revision serving under
                // the OLD binding, keeping published paths alive). The
                // binding/overrides update runs AFTER the deploy lands.
                if needs_deploy {
                    // Fix 1: two arms — real live digest vs degenerate/missing.
                    let detail = if live.is_some_and(digest_is_real) {
                        format!(
                            "digest {} → {} (blue-green re-stage)",
                            live.map(short_digest).unwrap_or("none"),
                            short_digest(&rb.digest)
                        )
                    } else {
                        format!(
                            "traffic split is not a single 100% entry \
                             → re-deploy reconverges ({})",
                            short_digest(&rb.digest)
                        )
                    };
                    steps.push(ApplyStep {
                        kind: ApplyStepKind::DeployBundle,
                        key: rb.spec.bundle_id.clone(),
                        action: ApplyAction::Update,
                        detail,
                        idempotency_key: None,
                        op: StepOp::Deploy {
                            // Overrides ride the deploy (applied after
                            // stage+warm, before the cut-over). The
                            // binding is reconciled by the update step
                            // AFTER the deploy lands, so None here —
                            // deploy rejects a differing binding.
                            payload: Box::new(deploy_payload(&env_id_str, rb, None)),
                            expected_digest: rb.digest.clone(),
                        },
                    });
                }

                if binding_differs || (overrides_differ && !needs_deploy) {
                    let route_binding = binding_differs.then(|| {
                        rb.spec
                            .route_binding
                            .clone()
                            .expect("binding_differs implies manifest binding")
                    });
                    let config_overrides = (overrides_differ && !needs_deploy)
                        .then(|| rb.spec.config_overrides.clone().expect("overrides_differ"));
                    let desired_hash = hash_json(&json!({
                        "route_binding": route_binding,
                        "config_overrides": config_overrides,
                    }));
                    let ikey = derive_idempotency_key(
                        &ctx.env_id,
                        ApplyStepKind::UpdateBundle.label(),
                        &rb.spec.bundle_id,
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
                        key: rb.spec.bundle_id.clone(),
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
                        rb.spec.bundle_id.clone(),
                        format!("digest match ({})", short_digest(&rb.digest)),
                    ));
                }
            }
        }
    }

    // 5. Endpoints (add → link → welcome-flow, per endpoint in manifest order).
    //    Reuses the match computed during validation (Fix 6); verify() re-matches
    //    the freshly reloaded env on purpose.
    for re in &ctx.endpoints {
        let ep = &re.spec;
        let matched = re.matched.as_ref();
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
    // Post-confirmation, pre-first-mutation artifact gate: re-hash every
    // bundle artifact to detect changes that occurred during the
    // (potentially unbounded) TTY confirmation pause. A changed artifact
    // aborts the whole apply before ANY step (including put-secret)
    // mutates the store. The per-Deploy-step re-check stays because later
    // steps in the same run can still race with external writes.
    for rb in &ctx.bundles {
        ensure_artifact_unchanged(&rb.resolved_path, &rb.digest)?;
    }

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
            step.action.as_str()
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
            StepOp::PutSecret { path } => {
                let value = ctx
                    .secret_values
                    .get(path)
                    .expect("validated: every put-secret step has a resolved value");
                super::secrets::put(
                    store,
                    &exec_flags,
                    Some(SecretsPutPayload {
                        environment_id: ctx.env_id.as_str().to_string(),
                        path: path.clone(),
                        value: value.expose().to_string(),
                        idempotency_key: step.idempotency_key.clone(),
                    }),
                )
                .map(|_| ())
            }
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
            } => resolve_endpoint_id(endpoint, &created_endpoints).and_then(|endpoint_id| {
                super::messaging::link_bundle(
                    store,
                    &exec_flags,
                    Some(EndpointLinkBundlePayload {
                        environment_id: ctx.env_id.as_str().to_string(),
                        endpoint_id,
                        bundle_id: bundle_id.clone(),
                        idempotency_key: step.idempotency_key.clone(),
                        updated_by: ctx.updated_by.clone(),
                    }),
                )
                .map(|_| ())
            }),
            StepOp::WelcomeFlow { endpoint, flow } => {
                resolve_endpoint_id(endpoint, &created_endpoints).and_then(|endpoint_id| {
                    super::messaging::set_welcome_flow(
                        store,
                        &exec_flags,
                        Some(EndpointSetWelcomeFlowPayload {
                            environment_id: ctx.env_id.as_str().to_string(),
                            endpoint_id,
                            bundle_id: flow.bundle_id.clone(),
                            pack_id: flow.pack_id.clone(),
                            flow_id: flow.flow_id.clone(),
                            idempotency_key: step.idempotency_key.clone(),
                            updated_by: ctx.updated_by.clone(),
                        }),
                    )
                    .map(|_| ())
                })
            }
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
/// job (PR-3), not apply's. Secrets are deliberately NOT verified: there is
/// no `get` until A9, and reader-side resolvability is exactly the doctor's
/// check — `put`'s own write-through already failed the step if the store
/// rejected it.
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

    for rb in &ctx.bundles {
        checked += 1;
        let Some(dep) = env
            .bundles
            .iter()
            .find(|d| d.bundle_id.as_str() == rb.spec.bundle_id && d.customer_id == rb.customer_id)
        else {
            failures.push(format!("bundle `{}` is not deployed", rb.spec.bundle_id));
            continue;
        };
        if !deployment_converged(&env, dep.deployment_id, &rb.digest) {
            failures.push(format!(
                "bundle `{}`: live revision digest is `{}`, expected `{}`",
                rb.spec.bundle_id,
                live_revision_digest(&env, dep.deployment_id).unwrap_or("none"),
                rb.digest
            ));
        }
        if let Some(binding) = &rb.spec.route_binding {
            let desired = into_route_binding(binding.clone());
            if desired != dep.route_binding {
                failures.push(format!(
                    "bundle `{}`: route_binding differs from the manifest",
                    rb.spec.bundle_id
                ));
            }
        }
        if let Some(overrides) = &rb.spec.config_overrides
            && *overrides != dep.config_overrides
        {
            failures.push(format!(
                "bundle `{}`: config_overrides differ from the manifest",
                rb.spec.bundle_id
            ));
        }
    }

    // Verify endpoints against the freshly reloaded env (re-match on
    // purpose — this IS the verify, not a cached result from validation).
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

/// Build a [`BundleDeployPayload`] from a resolved bundle, sharing the 5
/// fields common to both the create and re-deploy sites.
fn deploy_payload(
    env_id: &str,
    rb: &ResolvedBundle,
    route_binding: Option<RouteBindingPayload>,
) -> BundleDeployPayload {
    BundleDeployPayload {
        environment_id: env_id.to_string(),
        bundle_id: rb.spec.bundle_id.clone(),
        customer_id: rb.spec.customer_id.clone(),
        bundle_path: Some(rb.resolved_path.clone()),
        idempotency_key: None,
        config_overrides: rb.spec.config_overrides.clone(),
        route_binding,
    }
}

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

/// SHA-256 of the canonical JSON serialization (keys sorted by serde_json).
/// The output feeds deterministic idempotency keys, so the serialization
/// must stay canonical across builds (no `preserve_order` feature).
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
    if split.entries.len() != 1 || split.entries[0].weight_bps != super::deploy::FULL_TRAFFIC_BPS {
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

fn render_plan(steps: &[ApplyStep], warnings: &[String], missing: &[MissingItem]) {
    eprintln!("plan ({} step(s)):", steps.len());
    for step in steps {
        eprintln!(
            "  {:<22} {:<40} {:<7} {}",
            step.kind.label(),
            step.key,
            step.action.as_str(),
            step.detail
        );
    }
    for m in missing {
        eprintln!(
            "  missing: {:<14} {:<40} {}",
            m.kind.as_str(),
            m.key,
            m.source
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
    // Always-put rows: counted in `changed`, but not drift for `--check`
    // (see `ApplyAction::counts_as_drift`). Emitted in every mode so the
    // report schema doesn't vary by mode.
    let undiffable = steps
        .iter()
        .filter(|s| s.action == ApplyAction::Put)
        .count();
    let mut report = json!({
        "manifest_schema": ENV_MANIFEST_SCHEMA_V1,
        "environment_id": ctx.env_id.as_str(),
        "mode": mode,
        "steps": steps.iter().map(ApplyStep::to_json).collect::<Vec<_>>(),
        "changed": changed,
        "no_op": steps.len() - changed,
        "undiffable": undiffable,
        "missing": ctx.missing.iter().map(MissingItem::to_json).collect::<Vec<_>>(),
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
        bootstrap_env_trust_root, make_binding, make_bundle_deployment, make_env, make_revision,
        make_traffic_split,
    };
    use greentic_deploy_spec::{CapabilitySlot, RevisionLifecycle};
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

    fn run_mode(
        store: &LocalFsStore,
        manifest_path: &Path,
        mode: ApplyMode,
    ) -> Result<OpOutcome, OpError> {
        let flags = OpFlags {
            schema_only: false,
            answers: Some(manifest_path.to_path_buf()),
        };
        apply(
            store,
            &flags,
            ApplyOptions {
                mode,
                ..ApplyOptions::default()
            },
        )
    }

    fn run_apply(store: &LocalFsStore, manifest_path: &Path) -> Result<OpOutcome, OpError> {
        run_mode(store, manifest_path, ApplyMode::Apply)
    }

    fn run_dry(store: &LocalFsStore, manifest_path: &Path) -> Result<OpOutcome, OpError> {
        run_mode(store, manifest_path, ApplyMode::DryRun)
    }

    fn run_check(store: &LocalFsStore, manifest_path: &Path) -> Result<OpOutcome, OpError> {
        run_mode(store, manifest_path, ApplyMode::Check)
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

    // --- §9 follow-up: --check (CI convergence gate) ----------------------------

    #[test]
    fn check_fails_on_pending_diff_and_mutates_nothing() {
        let (dir, store) = seeded_store();
        let manifest_path = write_manifest(dir.path(), &full_manifest(&fixture()));

        let err = run_check(&store, &manifest_path).unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
        let msg = err.to_string();
        assert!(msg.contains("not converged"), "{msg}");
        assert!(msg.contains("4 pending change(s)"), "{msg}");

        let env = load_local(&store);
        assert!(env.bundles.is_empty(), "--check must not deploy");
        assert!(
            env.messaging_endpoints.is_empty(),
            "--check must not add endpoints"
        );
    }

    #[test]
    fn check_passes_on_converged_env() {
        let (dir, store) = seeded_store();
        let manifest_path = write_manifest(dir.path(), &full_manifest(&fixture()));
        run_apply(&store, &manifest_path).expect("apply succeeds");

        let outcome = run_check(&store, &manifest_path).expect("check passes on converged env");
        assert_eq!(outcome.result["mode"], "check");
        assert_eq!(outcome.result["changed"], 0, "result: {}", outcome.result);
        assert_eq!(outcome.result["undiffable"], 0);
        assert!(
            outcome.result.get("verify").is_none(),
            "check must not verify (nothing executed)"
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

    // --- PR-2: secrets[] -------------------------------------------------------

    /// [`seeded_store`] plus the default dev-store secrets binding `env init`
    /// would create (`make_env` binds no env-packs).
    fn seeded_store_with_dev_secrets() -> (tempfile::TempDir, LocalFsStore) {
        let (dir, store) = seeded_store();
        let mut env = load_local(&store);
        env.packs.push(make_binding(
            CapabilitySlot::Secrets,
            "greentic.secrets.dev-store@1.0.0",
        ));
        store.save(&env).unwrap();
        (dir, store)
    }

    fn run_with_lookup(
        store: &LocalFsStore,
        manifest_path: &Path,
        mode: ApplyMode,
        lookup: &dyn Fn(&str) -> Option<String>,
    ) -> Result<OpOutcome, OpError> {
        run_with_lookup_and_prompter(store, manifest_path, mode, lookup, None)
    }

    fn run_with_lookup_and_prompter(
        store: &LocalFsStore,
        manifest_path: &Path,
        mode: ApplyMode,
        lookup: &dyn Fn(&str) -> Option<String>,
        prompter: Option<&SecretPrompter>,
    ) -> Result<OpOutcome, OpError> {
        let flags = OpFlags {
            schema_only: false,
            answers: Some(manifest_path.to_path_buf()),
        };
        apply_with_lookups(
            store,
            &flags,
            ApplyOptions {
                mode,
                ..ApplyOptions::default()
            },
            lookup,
            prompter,
        )
    }

    use crate::cli::tests_common::dev_store_read;

    const SECRET_PATH: &str = "legal/_/messaging-telegram/telegram_bot_token";

    fn secrets_manifest(var: &str) -> Value {
        json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "secrets": [{"path": SECRET_PATH, "from_env": var}]
        })
    }

    #[test]
    fn secrets_e2e_put_writes_value_and_redacts() {
        let (dir, store) = seeded_store_with_dev_secrets();
        let manifest_path = write_manifest(dir.path(), &secrets_manifest("APPLY_LEGAL_BOT_TOKEN"));
        let lookup =
            |name: &str| (name == "APPLY_LEGAL_BOT_TOKEN").then(|| "tok-secret-9000".to_string());

        let outcome = run_with_lookup(&store, &manifest_path, ApplyMode::Apply, &lookup)
            .expect("apply succeeds");

        // The report names the env VAR and says `put` — never the value.
        let envelope = serde_json::to_string(&outcome).unwrap();
        assert!(
            !envelope.contains("tok-secret-9000"),
            "envelope must not leak the value: {envelope}"
        );
        assert!(envelope.contains("APPLY_LEGAL_BOT_TOKEN"), "{envelope}");
        let actions = step_actions(&outcome.result);
        assert!(
            actions.contains(&("put-secret".to_string(), "put".to_string())),
            "{actions:?}"
        );

        // Written through to the dev store the runtime reader resolves.
        let store_path = dir
            .path()
            .join("local")
            .join(super::super::secrets::DEV_STORE_RELATIVE);
        let bytes = dev_store_read(&store_path, &format!("secrets://local/{SECRET_PATH}"));
        assert_eq!(bytes, b"tok-secret-9000".to_vec());

        // The audit event carries a fresh (not deterministic) key and no value.
        let audit_path = dir.path().join("local/audit/events.jsonl");
        let put_ikeys = || -> Vec<String> {
            std::fs::read_to_string(&audit_path)
                .unwrap()
                .lines()
                .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                .filter(|e| e["noun"] == "secrets" && e["verb"] == "put")
                .map(|e| e["idempotency_key"].as_str().expect("ikey").to_string())
                .collect()
        };
        let audit = std::fs::read_to_string(&audit_path).unwrap();
        assert!(
            !audit.contains("tok-secret-9000"),
            "audit log must not leak the value"
        );
        assert_eq!(put_ikeys().len(), 1, "one put audit event: {audit}");

        // Always-put: a re-apply is NOT a no-op for the secret (cannot diff).
        let second =
            run_with_lookup(&store, &manifest_path, ApplyMode::Apply, &lookup).expect("re-apply");
        assert_eq!(second.result["changed"], 1, "{}", second.result);

        // Two invocations must mint DIFFERENT idempotency keys (fresh per
        // invocation — the contract after removing deterministic keys from
        // put-secret steps).
        let ikeys = put_ikeys();
        assert_eq!(ikeys.len(), 2, "two put events after re-apply: {ikeys:?}");
        assert_ne!(
            ikeys[0], ikeys[1],
            "two invocations must mint different keys"
        );
    }

    #[test]
    fn missing_or_empty_secret_env_var_fails_apply_before_mutation() {
        let (dir, store) = seeded_store_with_dev_secrets();
        let manifest_path = write_manifest(dir.path(), &secrets_manifest("APPLY_MISSING_VAR"));
        for value in [None, Some(String::new())] {
            let lookup = |_: &str| value.clone();
            let err =
                run_with_lookup(&store, &manifest_path, ApplyMode::Apply, &lookup).unwrap_err();
            match err {
                OpError::InvalidArgument(msg) => {
                    assert!(msg.contains("1 missing input(s)"), "got: {msg}");
                    assert!(msg.contains("APPLY_MISSING_VAR"), "got: {msg}");
                    assert!(msg.contains(SECRET_PATH), "got: {msg}");
                }
                other => panic!("expected InvalidArgument, got {other:?}"),
            }
        }
        // The missing gate fires before execute: nothing written.
        assert!(
            !dir.path()
                .join("local")
                .join(super::super::secrets::DEV_STORE_RELATIVE)
                .exists()
        );
        assert!(!dir.path().join("local/audit/events.jsonl").exists());
    }

    #[test]
    fn non_dev_store_backend_fails_at_validation() {
        let (dir, store) = seeded_store();
        let manifest_path = write_manifest(dir.path(), &secrets_manifest("APPLY_VAR"));
        let lookup = |_: &str| Some("v".to_string());

        // Existing env with NO secrets pack bound → the shared precondition
        // fires at validation time.
        let err = run_with_lookup(&store, &manifest_path, ApplyMode::Apply, &lookup).unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");

        // Non-dev-store backend → not-yet-implemented at validation time.
        let mut env = load_local(&store);
        env.packs.push(make_binding(
            CapabilitySlot::Secrets,
            "greentic.secrets.aws-sm@1.0.0",
        ));
        store.save(&env).unwrap();
        let err = run_with_lookup(&store, &manifest_path, ApplyMode::Apply, &lookup).unwrap_err();
        assert!(matches!(err, OpError::NotYetImplemented(_)), "got {err:?}");

        // Both failures pre-date execution: no audit events were appended.
        assert!(!dir.path().join("local/audit/events.jsonl").exists());
    }

    #[test]
    fn secrets_plan_orders_before_bundles_and_dry_run_writes_nothing() {
        let (dir, store) = seeded_store_with_dev_secrets();
        let mut manifest = full_manifest(&fixture());
        manifest["secrets"] = json!([{"path": SECRET_PATH, "from_env": "APPLY_ORDER_TOKEN"}]);
        let manifest_path = write_manifest(dir.path(), &manifest);
        let lookup = |_: &str| Some("tok-order".to_string());

        let plan =
            run_with_lookup(&store, &manifest_path, ApplyMode::DryRun, &lookup).expect("dry-run");
        let steps = plan.result["steps"].as_array().expect("steps");
        let pos = |kind: &str| {
            steps
                .iter()
                .position(|s| s["kind"] == kind)
                .unwrap_or_else(|| panic!("no `{kind}` step in {steps:?}"))
        };
        assert!(pos("ensure-environment") < pos("put-secret"));
        assert!(
            pos("put-secret") < pos("deploy-bundle"),
            "secrets must land before bundles so a fresh revision never \
             resolves a missing secret"
        );

        // Dry-run resolved the value but wrote nothing.
        assert!(
            !dir.path()
                .join("local")
                .join(super::super::secrets::DEV_STORE_RELATIVE)
                .exists(),
            "dry-run must not write the dev store"
        );
    }

    // `SecretValue`'s redacting-Debug property is pinned by its owning
    // module's test (`runtime_secrets::tests::secret_value_debug_is_redacted`).

    #[test]
    fn check_excludes_undiffable_secret_puts_but_counts_real_drift() {
        let (dir, store) = seeded_store_with_dev_secrets();
        let lookup =
            |name: &str| (name == "APPLY_LEGAL_BOT_TOKEN").then(|| "tok-secret-9000".to_string());

        // Converged env + a manifest whose only non-no-op row is the
        // always-put secret: excluded from the verdict — check passes,
        // reports the row as undiffable, and writes nothing.
        let manifest_path = write_manifest(dir.path(), &secrets_manifest("APPLY_LEGAL_BOT_TOKEN"));
        let outcome = run_with_lookup(&store, &manifest_path, ApplyMode::Check, &lookup)
            .expect("check passes");
        assert_eq!(outcome.result["mode"], "check");
        assert_eq!(outcome.result["undiffable"], 1, "{}", outcome.result);
        assert_eq!(
            outcome.result["changed"], 1,
            "the put row stays visible in the report: {}",
            outcome.result
        );
        assert!(
            !dir.path()
                .join("local")
                .join(super::super::secrets::DEV_STORE_RELATIVE)
                .exists(),
            "--check must not write the dev store"
        );

        // Mixed manifest: a pending bundle deploy is real drift — check
        // fails, and the count excludes the undiffable put row.
        let mut mixed = full_manifest(&fixture());
        mixed["secrets"] = json!([{"path": SECRET_PATH, "from_env": "APPLY_LEGAL_BOT_TOKEN"}]);
        let mixed_path = write_manifest(dir.path(), &mixed);
        let err = run_with_lookup(&store, &mixed_path, ApplyMode::Check, &lookup).unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
        assert!(
            err.to_string().contains("4 pending change(s)"),
            "put row must not count toward drift: {err}"
        );
    }

    // --- Adversarial-review fix 1: pre-mutation artifact re-hash gate ---

    #[test]
    fn tampered_artifact_aborts_before_any_secret_write() {
        // Between validation (digests computed) and execute, the
        // confirmation pause is unbounded. If an artifact changes during
        // the pause, the pre-mutation gate at the top of execute() must
        // abort the whole apply before ANY step (including put-secret)
        // mutates the store.
        let (dir, store) = seeded_store_with_dev_secrets();

        // Copy the real bundle to a temp file we can tamper.
        let tamper_bundle = dir.path().join("tamper.gtbundle");
        std::fs::copy(fixture(), &tamper_bundle).unwrap();

        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{"bundle_id": "quickstart", "bundle_path": &tamper_bundle}],
            "secrets": [{"path": SECRET_PATH, "from_env": "APPLY_TAMPER_TOKEN"}]
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        let lookup = |name: &str| (name == "APPLY_TAMPER_TOKEN").then(|| "tok-tamper".to_string());

        // Run the validation + diff pipeline directly (mirroring apply's
        // flow), then tamper the artifact, then call execute.
        let loaded: EnvManifest = super::super::load_answers(&manifest_path).unwrap();
        loaded.validate_shape().unwrap();
        let manifest_dir = manifest_path.parent().unwrap().to_path_buf();
        let ctx = resolve_and_validate(
            &store,
            loaded,
            &manifest_dir,
            "test".to_string(),
            &lookup,
            None,
        )
        .unwrap();
        let steps = diff(&store, &ctx).unwrap();

        // Tamper the bundle AFTER diff (simulating a change during the
        // confirmation pause).
        std::fs::write(&tamper_bundle, b"tampered bytes").unwrap();

        let err = execute(&store, &ctx, &steps).expect_err("tampered artifact must abort");
        assert!(
            matches!(&err, OpError::Conflict(msg) if msg.contains("changed since the plan")),
            "expected Conflict about artifact change, got: {err:?}"
        );

        // The dev-store file must NOT exist — no secret was written.
        assert!(
            !dir.path()
                .join("local")
                .join(super::super::secrets::DEV_STORE_RELATIVE)
                .exists(),
            "tampered artifact must abort before any secret write"
        );
    }

    // --- operator-surface PR-1: missing-inputs contract -------------------------

    #[test]
    fn missing_inputs_accumulate_across_secrets_and_bundles() {
        let (dir, store) = seeded_store_with_dev_secrets();
        let absent = dir.path().join("ghost.gtbundle");
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "secrets": [
                {"path": "legal/_/messaging-telegram/telegram_bot_token",
                 "from_env": "APPLY_VAR_A"},
                {"path": "accounting/_/messaging-telegram/telegram_bot_token",
                 "from_env": "APPLY_VAR_B"}
            ],
            "bundles": [{"bundle_id": "ghost", "bundle_path": absent}]
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        let lookup = |_: &str| None;

        // Dry-run: ALL THREE gaps in one report, stable order (secrets in
        // manifest order, then bundles), exit 0.
        let plan = run_with_lookup(&store, &manifest_path, ApplyMode::DryRun, &lookup)
            .expect("dry-run never fails on missing inputs");
        let rows: Vec<(String, String, String)> = plan.result["missing"]
            .as_array()
            .expect("missing array")
            .iter()
            .map(|m| {
                (
                    m["kind"].as_str().unwrap().to_string(),
                    m["key"].as_str().unwrap().to_string(),
                    m["source"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        assert_eq!(rows.len(), 3, "{rows:?}");
        assert_eq!(
            (rows[0].0.as_str(), rows[0].2.as_str()),
            ("secret_value", "env:APPLY_VAR_A")
        );
        assert_eq!(rows[0].1, "legal/_/messaging-telegram/telegram_bot_token");
        assert_eq!(
            (rows[1].0.as_str(), rows[1].2.as_str()),
            ("secret_value", "env:APPLY_VAR_B")
        );
        assert_eq!(rows[2].0, "bundle_artifact");
        assert_eq!(rows[2].1, "ghost");
        assert!(rows[2].2.starts_with("path:"), "{rows:?}");

        // Apply: the gate names all three gaps in ONE error, pre-mutation.
        let err = run_with_lookup(&store, &manifest_path, ApplyMode::Apply, &lookup).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("3 missing input(s)"), "{msg}");
        assert!(msg.contains("APPLY_VAR_A"), "{msg}");
        assert!(msg.contains("APPLY_VAR_B"), "{msg}");
        assert!(msg.contains("ghost"), "{msg}");
        assert!(!dir.path().join("local/audit/events.jsonl").exists());
    }

    #[test]
    fn check_reports_missing_but_excludes_it_from_the_verdict() {
        let (dir, store) = seeded_store_with_dev_secrets();
        // Converged env + one unset var: check exits 0 — a CI convergence
        // gate must be runnable without holding credentials — and reports
        // the gap.
        let manifest_path = write_manifest(dir.path(), &secrets_manifest("APPLY_UNSET_CI_VAR"));
        let lookup = |_: &str| None;
        let outcome = run_with_lookup(&store, &manifest_path, ApplyMode::Check, &lookup)
            .expect("check passes without the secret value");
        assert_eq!(outcome.result["mode"], "check");
        assert_eq!(
            outcome.result["missing"].as_array().unwrap().len(),
            1,
            "{}",
            outcome.result
        );
        assert_eq!(outcome.result["undiffable"], 1);

        // Real drift still fails check, with or without the values.
        let mut mixed = full_manifest(&fixture());
        mixed["secrets"] = json!([{"path": SECRET_PATH, "from_env": "APPLY_UNSET_CI_VAR"}]);
        let mixed_path = write_manifest(dir.path(), &mixed);
        let err = run_with_lookup(&store, &mixed_path, ApplyMode::Check, &lookup).unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn prompter_fills_missing_secret_and_plan_says_prompted() {
        let (dir, store) = seeded_store_with_dev_secrets();
        let manifest_path = write_manifest(dir.path(), &secrets_manifest("APPLY_PROMPT_VAR"));
        let lookup = |_: &str| None;
        let prompter = |path: &str, from_env: &str| {
            assert_eq!(path, SECRET_PATH);
            assert_eq!(from_env, "APPLY_PROMPT_VAR");
            Some("tok-prompted-1".to_string())
        };

        let outcome = run_with_lookup_and_prompter(
            &store,
            &manifest_path,
            ApplyMode::Apply,
            &lookup,
            Some(&prompter),
        )
        .expect("prompted apply succeeds");

        // The plan row says `prompted` (not `from $VAR`), the report's
        // missing list is empty, and the value never leaks anywhere.
        let envelope = serde_json::to_string(&outcome).unwrap();
        assert!(!envelope.contains("tok-prompted-1"), "{envelope}");
        let steps = outcome.result["steps"].as_array().unwrap();
        let put = steps.iter().find(|s| s["kind"] == "put-secret").unwrap();
        assert_eq!(put["detail"], "prompted (cannot diff until A9)");
        assert!(outcome.result["missing"].as_array().unwrap().is_empty());

        // The prompted value reached the dev store the runtime reads.
        let store_path = dir
            .path()
            .join("local")
            .join(super::super::secrets::DEV_STORE_RELATIVE);
        let bytes = dev_store_read(&store_path, &format!("secrets://local/{SECRET_PATH}"));
        assert_eq!(bytes, b"tok-prompted-1".to_vec());

        // Audit must not leak it either.
        let audit = std::fs::read_to_string(dir.path().join("local/audit/events.jsonl")).unwrap();
        assert!(!audit.contains("tok-prompted-1"));
    }

    #[test]
    fn prompter_decline_leaves_input_missing() {
        let (dir, store) = seeded_store_with_dev_secrets();
        let manifest_path = write_manifest(dir.path(), &secrets_manifest("APPLY_DECLINE_VAR"));
        let lookup = |_: &str| None;
        let prompter = |_: &str, _: &str| None;
        let err = run_with_lookup_and_prompter(
            &store,
            &manifest_path,
            ApplyMode::Apply,
            &lookup,
            Some(&prompter),
        )
        .unwrap_err();
        assert!(err.to_string().contains("1 missing input(s)"), "{err}");
        assert!(!dir.path().join("local/audit/events.jsonl").exists());
    }

    #[test]
    fn emit_answers_template_writes_valid_manifest_and_touches_nothing() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let out = dir.path().join("template.env.json");
        let outcome = apply(
            &store,
            &OpFlags::default(), // template needs no --answers
            ApplyOptions {
                emit_answers_template: Some(out.clone()),
                ..ApplyOptions::default()
            },
        )
        .expect("template emit succeeds");
        assert_eq!(outcome.result["mode"], "emit-answers-template");

        // What lands on disk parses under deny_unknown_fields and is
        // shape-valid as-is (the env_manifest guard test pins the source;
        // this pins the written artifact).
        let written: EnvManifest = serde_json::from_slice(&std::fs::read(&out).unwrap())
            .expect("written template parses as EnvManifest");
        written
            .validate_shape()
            .expect("written template is shape-valid");
        // No env/store state was created.
        assert!(!store.exists(&EnvId::try_from("local").unwrap()).unwrap());
    }

    // --- Fix 8: welcome-flow reachability lives in env-side validation only ---

    #[test]
    fn welcome_flow_not_in_links_rejected_by_env_validation() {
        // Manifest declares a welcome_flow whose bundle_id IS in bundles[] but
        // NOT in that endpoint's links[]. Shape validation passes (the check
        // was removed from validate_shape); env-side validation catches it.
        let (dir, store) = seeded_store();
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{"bundle_id": "quickstart", "bundle_path": fixture()}],
            "messaging_endpoints": [{
                "name": "n",
                "provider_type": "messaging.telegram.bot",
                "links": [],
                "welcome_flow": {"bundle_id": "quickstart", "pack_id": "p", "flow_id": "f"}
            }]
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        let err = run_apply(&store, &manifest_path).unwrap_err();
        match err {
            OpError::InvalidArgument(msg) => {
                assert!(msg.contains("links[]"), "got: {msg}");
            }
            other => panic!("expected InvalidArgument mentioning links[], got {other:?}"),
        }
        // No mutation: env-side validation fires before any step.
        let env = load_local(&store);
        assert!(env.messaging_endpoints.is_empty());
        assert!(env.revisions.is_empty());
    }

    // --- Fix 10a: hash_json determinism pin ---

    #[test]
    fn hash_json_output_is_stable() {
        // Pins idempotency-key stability across builds. serde_json without
        // preserve_order sorts keys, so {"b":1,"a":[true,"x"]} serializes
        // as {"a":[true,"x"],"b":1}.
        assert_eq!(
            hash_json(&json!({"b": 1, "a": [true, "x"]})),
            "f15ef113d6e0c876b9ea9e90ebc36ad3f8b350d44634ba2fc407e978fb8cebeb"
        );
    }

    // --- Fix 10c: deploy rejects differing route binding (contract pin) ---

    #[test]
    fn deploy_rejects_differing_binding_contract_pin() {
        // Apply relies on deploy-first / route_binding: None ordering for the
        // re-deploy site. That ordering only works because deploy rejects a
        // differing binding on an existing deployment (returning Conflict).
        // This test pins that contract so a future change to deploy's binding
        // check breaks the apply tests explicitly.
        let (_dir, store) = seeded_store();
        let mut p = super::super::deploy::BundleDeployPayload {
            environment_id: "local".to_string(),
            bundle_id: "quickstart".to_string(),
            customer_id: None,
            bundle_path: Some(fixture()),
            idempotency_key: None,
            config_overrides: None,
            route_binding: Some(super::super::bundles::RouteBindingPayload {
                hosts: Vec::new(),
                path_prefixes: vec!["/v1".to_string()],
                tenant_selector: None,
            }),
        };
        super::super::deploy::deploy(&store, &OpFlags::default(), Some(p.clone()))
            .expect("first deploy");
        // Re-deploy with a DIFFERENT binding.
        p.route_binding = Some(super::super::bundles::RouteBindingPayload {
            hosts: Vec::new(),
            path_prefixes: vec!["/v2".to_string()],
            tenant_selector: None,
        });
        let err = super::super::deploy::deploy(&store, &OpFlags::default(), Some(p)).unwrap_err();
        match err {
            OpError::Conflict(msg) => {
                assert!(
                    msg.contains("route_binding differs"),
                    "expected Conflict about differing binding, got: {msg}"
                );
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }
}
