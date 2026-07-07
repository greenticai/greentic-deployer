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
//!   without holding credentials).
//!
//! The `--emit-answers-template <path>` shortcut writes a skeleton manifest
//! to start from — it is dispatched as a peer verb mode
//! ([`emit_answers_template`]) before the apply engine is entered, because
//! it needs no store, no manifest, and no flags.
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
    BundleDeploymentStatus, CapabilitySlot, CustomerId, DeploymentId, EnvId, Environment,
    MessagingEndpoint, RouteBinding,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::environment::{EnvironmentStore, LocalFsStore, trust_root as store_trust_root};
use crate::runtime_secrets::SecretValue;

use super::bundles::{
    BundleUpdatePayload, RevenueShareEntryPayload, RouteBindingPayload, convert_revenue_share,
    into_route_binding,
};
use super::config::ConfigSetPayload;
use super::deploy::BundleDeployPayload;
use super::env::EnvInitPayload;
use super::env_manifest::{
    ENV_MANIFEST_SCHEMA_V1, EnvManifest, ManifestBundle, ManifestEndpoint, ManifestRevision,
    ManifestWelcomeFlow, TrustRootDirective, compute_effective_weights_bps, manifest_schema,
};
use super::env_packs::EnvPackBindingPayload;
use super::extensions::ExtensionBindingPayload;
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
    UpdateHostConfig,
    BootstrapTrustRoot,
    AddPackBinding,
    UpdatePackBinding,
    PutSecret,
    DeployBundle,
    DeploySplit,
    UpdateBundle,
    AddExtension,
    UpdateExtension,
    AddEndpoint,
    LinkEndpoint,
    SetWelcomeFlow,
}

impl ApplyStepKind {
    fn label(self) -> &'static str {
        match self {
            ApplyStepKind::EnsureEnvironment => "ensure-environment",
            ApplyStepKind::UpdateHostConfig => "update-host-config",
            ApplyStepKind::BootstrapTrustRoot => "bootstrap-trust-root",
            ApplyStepKind::AddPackBinding => "add-pack-binding",
            ApplyStepKind::UpdatePackBinding => "update-pack-binding",
            ApplyStepKind::PutSecret => "put-secret",
            ApplyStepKind::DeployBundle => "deploy-bundle",
            ApplyStepKind::DeploySplit => "deploy-split",
            ApplyStepKind::UpdateBundle => "update-bundle",
            ApplyStepKind::AddExtension => "add-extension",
            ApplyStepKind::UpdateExtension => "update-extension",
            ApplyStepKind::AddEndpoint => "add-endpoint",
            ApplyStepKind::LinkEndpoint => "link-endpoint",
            ApplyStepKind::SetWelcomeFlow => "set-welcome-flow",
        }
    }
}

/// One revision inside a [`StepOp::DeploySplit`]. Carries the resolved
/// artifact path and digest for TOCTOU re-verification, plus the effective
/// weight already computed by [`compute_effective_weights_bps`].
#[derive(Debug, Clone)]
struct SplitRevisionEntry {
    name: String,
    resolved_path: PathBuf,
    expected_digest: String,
    weight_bps: u32,
    drain_seconds: Option<u32>,
    /// OCI/repo/store pull ref for the staged revision (K8s boot pull);
    /// `None` = local-serve only.
    bundle_source_uri: Option<String>,
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
    /// Multi-revision traffic-split deploy: stage each revision, warm it,
    /// then set the combined traffic split. Each entry carries its own
    /// artifact path and digest for TOCTOU re-verification.
    DeploySplit {
        env_id: String,
        bundle_id: String,
        customer_id: Option<String>,
        config_overrides: Option<BTreeMap<String, BTreeMap<String, Value>>>,
        route_binding: Option<RouteBindingPayload>,
        /// Revenue-share split applied on the FRESH-add path (`None` =
        /// `greentic@10000`). Reconciled via `bundles update` for an
        /// existing deployment.
        revenue_share: Option<Vec<RevenueShareEntryPayload>>,
        revisions: Vec<SplitRevisionEntry>,
    },
    UpdateHostConfig(Box<ConfigSetPayload>),
    AddPackBinding(Box<EnvPackBindingPayload>),
    UpdatePackBinding(Box<EnvPackBindingPayload>),
    AddExtension(Box<ExtensionBindingPayload>),
    UpdateExtension(Box<ExtensionBindingPayload>),
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

/// One resolved revision inside a multi-revision bundle entry.
struct ResolvedRevision {
    spec: ManifestRevision,
    resolved_path: PathBuf,
    digest: String,
    /// Effective weight in basis points, computed by
    /// [`compute_effective_weights_bps`].
    weight_bps: u32,
}

/// A manifest bundle entry paired with its resolved artifact metadata.
/// For single-revision entries (`bundle_path` form), `revisions` holds
/// exactly one entry at full weight. Multi-revision entries hold one per
/// declared revision.
struct ResolvedBundle {
    spec: ManifestBundle,
    /// Billing principal resolved during validation (from
    /// `resolve_customer_id`). Used to match deployments by the same
    /// `(bundle_id, customer_id)` pair that `op deploy` keys on.
    customer_id: CustomerId,
    /// Resolved revisions. Always non-empty after validation.
    revisions: Vec<ResolvedRevision>,
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
    /// Paste-sourced secret paths already present in the env's store (no value
    /// to collect or put — store-as-source-of-truth). These get neither a put
    /// step nor a missing-input report; `diff` skips them entirely.
    store_satisfied_paths: BTreeSet<String>,
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
    /// Directory of the manifest file. Pack-binding `answers_ref`s resolve
    /// against it, and apply stages them into the env store so reconcile
    /// (which resolves against the env dir) can find them.
    manifest_dir: PathBuf,
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
    pub(super) fn as_str(self) -> &'static str {
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
///
/// The `--emit-answers-template` shortcut is dispatched as a peer verb
/// mode ([`emit_answers_template`]) before `ApplyOptions` is constructed,
/// so it does not appear here.
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
    /// Pre-collected values for paste-sourced secrets (manifest `from_env`
    /// absent), keyed by the manifest secret `path`. An interactive author
    /// (the `gtc setup --env` wizard) collects each value once and hands it
    /// here so apply does not prompt again; env-sourced secrets ignore this.
    /// Never serialized — `SecretValue`'s `Debug` renders a placeholder.
    pub prefilled_secrets: BTreeMap<String, SecretValue>,
}

/// Write the skeleton `greentic.env-manifest.v1` template to `path`.
///
/// This is the peer verb mode for `--emit-answers-template`: it needs no
/// store, no manifest, and no flags — dispatched before `apply` is
/// entered so the template write is decoupled from the apply engine's
/// precondition stack.
pub fn emit_answers_template(path: &Path) -> Result<OpOutcome, OpError> {
    std::fs::write(path, super::env_manifest::MANIFEST_TEMPLATE_JSON).map_err(|source| {
        OpError::Io {
            path: path.to_path_buf(),
            source,
        }
    })?;
    Ok(OpOutcome::new(
        NOUN,
        VERB,
        json!({
            "manifest_schema": ENV_MANIFEST_SCHEMA_V1,
            "mode": "emit-answers-template",
            "path": path,
        }),
    ))
}

/// `gtc op env apply --answers <manifest.json> [--dry-run | --check |
/// --non-interactive] [--updated-by <who>] [--yes]`.
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

/// Asked for a secret value: `(manifest path, from_env name) -> value`.
/// For an env-sourced secret this is the fallback when `$from_env` is unset;
/// for a paste-sourced secret (`from_env` absent) the caller passes an empty
/// `from_env`, and this is the primary collection path. `None` means "still
/// missing" — the path lands in the missing-inputs report.
type SecretPrompter = dyn Fn(&str, &str) -> Option<String>;

/// Masked TTY prompt for one secret value. Empty input declines — the path
/// stays missing and apply aborts with the full report. The value lives only
/// in the in-memory [`SecretValue`] map, exactly like an env-resolved one; it
/// never reaches the manifest, plan, report, or audit. An empty `from_env`
/// marks a paste-sourced secret (no env var to name), changing the wording
/// from "unset variable" to a plain value prompt.
fn prompt_secret_value(path: &str, from_env: &str) -> Option<String> {
    let prompt = if from_env.is_empty() {
        format!("secret `{path}`: enter value (hidden; empty to abort): ")
    } else {
        format!("secret `{path}`: ${from_env} is unset — enter value (hidden; empty to abort): ")
    };
    let value = rpassword::prompt_password(prompt).ok()?;
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
    let ApplyOptions {
        mode,
        updated_by,
        yes,
        non_interactive,
        prefilled_secrets,
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
        &prefilled_secrets,
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
    prefilled_secrets: &BTreeMap<String, SecretValue>,
) -> Result<ApplyContext, OpError> {
    let env_id = EnvId::try_from(manifest.environment.id.as_str())
        .map_err(|e| OpError::InvalidArgument(format!("environment.id: {e}")))?;
    let canonical_public_base_url =
        super::env::parse_optional_public_base_url(&manifest.environment.public_base_url)?;

    let env = if store.exists(&env_id)? {
        Some(store.load(&env_id)?)
    } else {
        // `env apply` bootstraps only the `local` env (its `env init` step
        // seeds the default bindings). A named env is first-class on the local
        // store but must be created explicitly first — `apply` reconciles an
        // existing named env, it does not bootstrap one. Surface a clear error
        // at plan time rather than failing mid-execute.
        if env_id.as_str() != crate::defaults::LOCAL_ENV_ID {
            return Err(OpError::NotFound(format!(
                "environment `{env_id}` not found — `env apply` reconciles an existing \
                 named environment but does not create one. Run `op env create {env_id}` \
                 first, then re-run apply (or use `local`, which apply bootstraps)."
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
    //
    // Per-secret resolution by source:
    // - env-sourced (`from_env: Some`): read `$from_env`, falling back to an
    //   interactive masked prompt when it is unset (today's behavior).
    // - paste-sourced (`from_env: None`): use an author-supplied value
    //   (`prefilled_secrets`, the wizard hand-off) if present; else, if the
    //   value is already in the env's secrets store, it is satisfied with no
    //   re-prompt and no put (the store is the source of truth for pasted
    //   values); else prompt interactively; else report it missing.
    let env_dir = store.env_dir(&env_id)?;
    let mut missing = Vec::new();
    let mut secret_values = BTreeMap::new();
    let mut prompted_paths = BTreeSet::new();
    let mut store_satisfied_paths = BTreeSet::new();
    for s in &manifest.secrets {
        let value = match &s.from_env {
            Some(from_env) => match env_lookup(from_env).filter(|v| !v.is_empty()) {
                Some(v) => Some(v),
                None => prompter.and_then(|p| {
                    let v = p(&s.path, from_env).filter(|v| !v.is_empty());
                    if v.is_some() {
                        prompted_paths.insert(s.path.clone());
                    }
                    v
                }),
            },
            None => {
                // An author-supplied value wins. An EMPTY prefilled value is
                // treated as no value — consistent with the env/prompt branches
                // (which filter empties) — so it falls through to the store
                // check / prompt / missing path instead of reaching
                // `secrets::put`, which rejects empties only at execute, after
                // earlier steps have already mutated state.
                let prefilled = prefilled_secrets
                    .get(&s.path)
                    .map(|value| value.expose())
                    .filter(|value| !value.is_empty());
                if let Some(value) = prefilled {
                    Some(value.to_string())
                } else if super::secrets::dev_store_has(&env_dir, &env_id, &s.path)? {
                    // Already stored — nothing to collect or put. Skip
                    // entirely: not a value, not a missing input.
                    store_satisfied_paths.insert(s.path.clone());
                    continue;
                } else {
                    // Empty `from_env` selects the paste-prompt wording.
                    prompter.and_then(|p| p(&s.path, "").filter(|v| !v.is_empty()))
                }
            }
        };
        match value {
            Some(v) => {
                secret_values.insert(s.path.clone(), SecretValue::from(v));
            }
            None => missing.push(MissingItem {
                kind: MissingKind::SecretValue,
                key: s.path.clone(),
                source: match &s.from_env {
                    Some(from_env) => format!("env:{from_env}"),
                    None => "paste".to_string(),
                },
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

        // Single-revision, remote-only source: no local `bundle_path`. Fetch the
        // artifact from `bundle_source_uri` so it stages exactly like a local
        // bundle, then verify any declared digest. (Multi-revision remote-only
        // is a follow-up; `validate_shape` permits URI-only for the
        // single-revision form only.)
        if b.bundle_path.is_none() && b.revisions.is_none() {
            let uri = b
                .bundle_source_uri
                .as_deref()
                .expect("validate_shape: single-revision URI-only carries bundle_source_uri");
            let fetched = match super::bundle_fetch::fetch_bundle_uri_to_local(uri) {
                Ok(path) => path,
                // Unreachable registry / missing artifact is an input gap,
                // reported like an absent local file (skippable, not fatal).
                Err(OpError::Fetch(message)) => {
                    missing.push(MissingItem {
                        kind: MissingKind::BundleArtifact,
                        key: b.bundle_id.clone(),
                        source: format!("uri:{uri} ({message})"),
                    });
                    continue;
                }
                // A malformed / unsupported URI is a manifest bug — fail fast.
                Err(other) => return Err(other),
            };
            let digest = resolved_artifact_digest(
                &fetched,
                b.bundle_digest.as_deref(),
                &format!("bundle `{}`", b.bundle_id),
            )?;
            resolved_bundles.push(ResolvedBundle {
                spec: b.clone(),
                customer_id,
                revisions: vec![ResolvedRevision {
                    spec: ManifestRevision {
                        name: "default".to_string(),
                        // Vestigial: `deploy_payload` reads `resolved_path`, not
                        // this. The fetched cache file is the local location.
                        bundle_path: fetched.clone(),
                        weight_percent: None,
                        weight_bps: Some(super::deploy::FULL_TRAFFIC_BPS),
                        drain_seconds: None,
                        abort_metrics: Vec::new(),
                        // The single-revision pull ref lives on the bundle
                        // (`rb.spec.bundle_source_uri`, read by `deploy_payload`).
                        bundle_source_uri: None,
                        bundle_digest: None,
                    },
                    resolved_path: fetched,
                    digest,
                    weight_bps: super::deploy::FULL_TRAFFIC_BPS,
                }],
            });
            continue;
        }

        // Resolve each artifact path (single-revision or multi-revision).
        let artifact_specs: Vec<(&std::path::Path, Option<&ManifestRevision>)> =
            if let Some(bp) = &b.bundle_path {
                vec![(bp.as_path(), None)]
            } else if let Some(revs) = &b.revisions {
                revs.iter()
                    .map(|r| (r.bundle_path.as_path(), Some(r)))
                    .collect()
            } else {
                // validate_shape already rejects this, but be safe.
                continue;
            };

        let mut any_missing = false;
        let mut resolved_revs = Vec::with_capacity(artifact_specs.len());

        // For multi-revision, compute effective weights (validated by
        // validate_shape). Single-revision always gets FULL_TRAFFIC_BPS.
        let weights: Vec<u32> = if let Some(revs) = &b.revisions {
            compute_effective_weights_bps(revs)
        } else {
            vec![super::deploy::FULL_TRAFFIC_BPS]
        };

        for (i, (artifact_path, rev_spec)) in artifact_specs.iter().enumerate() {
            let resolved_path = if artifact_path.is_absolute() {
                artifact_path.to_path_buf()
            } else {
                manifest_dir.join(artifact_path)
            };
            if !resolved_path.is_file() {
                let key = match rev_spec {
                    Some(r) => format!("{}:{}", b.bundle_id, r.name),
                    None => b.bundle_id.clone(),
                };
                missing.push(MissingItem {
                    kind: MissingKind::BundleArtifact,
                    key,
                    source: format!("path:{}", resolved_path.display()),
                });
                any_missing = true;
                continue;
            }
            let declared_digest = match rev_spec {
                Some(r) => r.bundle_digest.as_deref(),
                None => b.bundle_digest.as_deref(),
            };
            let location = match rev_spec {
                Some(r) => format!("bundle `{}`, revision `{}`", b.bundle_id, r.name),
                None => format!("bundle `{}`", b.bundle_id),
            };
            let digest = resolved_artifact_digest(&resolved_path, declared_digest, &location)?;
            let spec = rev_spec.cloned().unwrap_or_else(|| {
                // Synthesize a ManifestRevision for single-revision entries.
                ManifestRevision {
                    name: "default".to_string(),
                    bundle_path: b
                        .bundle_path
                        .clone()
                        .expect("single-revision has bundle_path"),
                    weight_percent: None,
                    weight_bps: Some(super::deploy::FULL_TRAFFIC_BPS),
                    drain_seconds: None,
                    abort_metrics: Vec::new(),
                    // Single-revision pull ref lives on the bundle
                    // (`rb.spec.bundle_source_uri`, read by `deploy_payload`),
                    // not on this synthetic revision.
                    bundle_source_uri: None,
                    bundle_digest: None,
                }
            });
            resolved_revs.push(ResolvedRevision {
                spec,
                resolved_path,
                digest,
                weight_bps: weights[i],
            });
        }

        if any_missing {
            continue;
        }

        resolved_bundles.push(ResolvedBundle {
            spec: b.clone(),
            customer_id,
            revisions: resolved_revs,
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

    // Validate that every declared `answers_ref` resolves to an existing file
    // relative to the manifest directory. The schema contract says "relative to
    // the manifest", so catch missing files at plan time rather than letting a
    // later `op env render` fail with a confusing path error.
    // NOTE: the stored path is the raw manifest-relative value. The consumer
    // (`load_render_answers`) resolves relative to the *env* directory, which
    // may differ. A future iteration should copy the file into the env dir or
    // store an env-relative path; for now we at least fail fast on a typo.
    for p in &manifest.packs {
        if let Some(ar) = &p.answers_ref {
            let resolved = if ar.is_absolute() {
                ar.clone()
            } else {
                manifest_dir.join(ar)
            };
            if !resolved.is_file() {
                return Err(OpError::InvalidArgument(format!(
                    "packs[] slot `{}`: answers_ref `{}` does not exist (resolved to `{}`)",
                    p.slot,
                    ar.display(),
                    resolved.display()
                )));
            }
        }
    }
    for ext in &manifest.extensions {
        if let Some(ar) = &ext.answers_ref {
            let resolved = if ar.is_absolute() {
                ar.clone()
            } else {
                manifest_dir.join(ar)
            };
            if !resolved.is_file() {
                return Err(OpError::InvalidArgument(format!(
                    "extensions[] kind `{}`: answers_ref `{}` does not exist (resolved to `{}`)",
                    ext.kind,
                    ar.display(),
                    resolved.display()
                )));
            }
        }
    }

    Ok(ApplyContext {
        env_id,
        manifest,
        secret_values,
        prompted_paths,
        store_satisfied_paths,
        bundles: resolved_bundles,
        endpoints: resolved_endpoints,
        env,
        canonical_public_base_url,
        missing,
        warnings,
        updated_by,
        manifest_dir: manifest_dir.to_path_buf(),
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

    // 1. EnsureEnvironment. `ctx.env == None` only ever reaches here for the
    //    `local` env — `resolve_and_validate` rejects a non-existent non-local
    //    env before diffing (non-local creation is reserved for the remote
    //    operator store, A7).
    match &ctx.env {
        None => {
            steps.push(ApplyStep {
                kind: ApplyStepKind::EnsureEnvironment,
                key: env_id_str.clone(),
                action: ApplyAction::Create,
                detail: "env init (local bootstrap: default env-pack bindings + trust-root seed)"
                    .to_string(),
                idempotency_key: None,
                op: StepOp::EnvInit {
                    public_base_url: ctx.canonical_public_base_url.clone(),
                },
            });
        }
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

    // 2. UpdateHostConfig (name, region, tenant_org_id, listen_addr, gui_enabled).
    //    Compares declared manifest fields against the live env; any declared
    //    field that differs emits ONE UpdateHostConfig step. On a fresh env
    //    (env == None) the host-config update is deferred to after the
    //    EnsureEnvironment execute creates the env.
    if let Some(env) = &ctx.env {
        let me = &ctx.manifest.environment;
        let name_differs = me.name.as_ref().is_some_and(|n| *n != env.name);
        let region_differs = me
            .region
            .as_ref()
            .is_some_and(|r| env.host_config.region.as_deref() != Some(r.as_str()));
        let tenant_org_differs = me
            .tenant_org_id
            .as_ref()
            .is_some_and(|t| env.host_config.tenant_org_id.as_deref() != Some(t.as_str()));
        let listen_addr_differs = me.listen_addr.as_ref().is_some_and(|la| {
            let parsed: std::net::SocketAddr = la
                .parse()
                .expect("validate_shape already validated listen_addr");
            env.host_config.listen_addr != Some(parsed)
        });
        // Compares against the RAW stored value (like every other host-config
        // field) — declaring a value always persists it; the env-id default
        // (on for local) is resolved by the runtime only when unset.
        let gui_enabled_differs = me
            .gui_enabled
            .is_some_and(|g| env.host_config.gui_enabled != Some(g));

        if name_differs
            || region_differs
            || tenant_org_differs
            || listen_addr_differs
            || gui_enabled_differs
        {
            let mut fields = Vec::new();
            if name_differs {
                fields.push("name");
            }
            if region_differs {
                fields.push("region");
            }
            if tenant_org_differs {
                fields.push("tenant_org_id");
            }
            if listen_addr_differs {
                fields.push("listen_addr");
            }
            if gui_enabled_differs {
                fields.push("gui_enabled");
            }
            let desired_hash = hash_json(&json!({
                "name": me.name,
                "region": me.region,
                "tenant_org_id": me.tenant_org_id,
                "listen_addr": me.listen_addr,
                "gui_enabled": me.gui_enabled,
            }));
            let ikey = derive_idempotency_key(
                &ctx.env_id,
                ApplyStepKind::UpdateHostConfig.label(),
                &env_id_str,
                &desired_hash,
            );
            steps.push(ApplyStep {
                kind: ApplyStepKind::UpdateHostConfig,
                key: env_id_str.clone(),
                action: ApplyAction::Update,
                detail: format!("set {}", fields.join(", ")),
                idempotency_key: Some(ikey),
                op: StepOp::UpdateHostConfig(Box::new(ConfigSetPayload {
                    environment_id: env_id_str.clone(),
                    name: me.name.clone(),
                    region: me.region.clone(),
                    tenant_org_id: me.tenant_org_id.clone(),
                    listen_addr: me.listen_addr.clone(),
                    public_base_url: None, // public_base_url is handled by SetPublicUrl
                    gui_enabled: me.gui_enabled,
                })),
            });
        } else if me.declares_host_config() {
            steps.push(ApplyStep::no_op(
                ApplyStepKind::UpdateHostConfig,
                env_id_str.clone(),
                "host-config unchanged",
            ));
        }
    } else {
        // Fresh env (always `local` here — see EnsureEnvironment). `env init`
        // does NOT thread name/region/tenant_org_id/listen_addr, so a declared
        // host-config is applied by a deferred UpdateHostConfig step that runs
        // after the env is created.
        let me = &ctx.manifest.environment;
        if me.declares_host_config() {
            steps.push(ApplyStep {
                kind: ApplyStepKind::UpdateHostConfig,
                key: env_id_str.clone(),
                action: ApplyAction::Create,
                detail: "set host-config on fresh env".to_string(),
                idempotency_key: None,
                op: StepOp::UpdateHostConfig(Box::new(ConfigSetPayload {
                    environment_id: env_id_str.clone(),
                    name: me.name.clone(),
                    region: me.region.clone(),
                    tenant_org_id: me.tenant_org_id.clone(),
                    listen_addr: me.listen_addr.clone(),
                    public_base_url: None,
                    gui_enabled: me.gui_enabled,
                })),
            });
        }
    }

    // 3. BootstrapTrustRoot.
    if ctx.manifest.trust_root == Some(TrustRootDirective::Bootstrap) {
        steps.push(trust_root_step(store, ctx)?);
    }

    // 4. Env-packs — each manifest pack binds one core capability slot.
    //    Look up the existing binding by slot; absent → add, differs → update.
    //
    //    On a fresh env (`ctx.env == None`, always `local` here) the preceding
    //    EnsureEnvironment step will create the env with five default bindings
    //    (deployer, secrets, telemetry, sessions, state). We must diff against
    //    those defaults so packs targeting a default slot emit UpdatePackBinding
    //    (or no-op) instead of an unconditional AddPackBinding that would fail
    //    with `SlotAlreadyBound` after `env init` runs.
    let default_bindings = if ctx.env.is_none() {
        Some(
            crate::defaults::local_pack_bindings()
                .map_err(|e| OpError::InvalidArgument(format!("default pack bindings: {e}")))?,
        )
    } else {
        None
    };
    for mp in &ctx.manifest.packs {
        let existing = match &ctx.env {
            Some(e) => e.pack_for_slot(mp.slot),
            None => default_bindings
                .as_ref()
                .and_then(|bs| bs.iter().find(|b| b.slot == mp.slot)),
        };
        match existing {
            None => {
                let desired_hash = hash_json(&json!({
                    "slot": mp.slot.to_string(),
                    "kind": mp.kind,
                    "pack_ref": mp.pack_ref,
                    "answers_ref": mp.answers_ref,
                }));
                let ikey = derive_idempotency_key(
                    &ctx.env_id,
                    ApplyStepKind::AddPackBinding.label(),
                    &mp.slot.to_string(),
                    &desired_hash,
                );
                steps.push(ApplyStep {
                    kind: ApplyStepKind::AddPackBinding,
                    key: mp.slot.to_string(),
                    action: ApplyAction::Create,
                    detail: format!("{} ({})", mp.kind, mp.pack_ref),
                    idempotency_key: Some(ikey.clone()),
                    op: StepOp::AddPackBinding(Box::new(EnvPackBindingPayload {
                        environment_id: env_id_str.clone(),
                        slot: mp.slot,
                        kind: mp.kind.clone(),
                        pack_ref: mp.pack_ref.clone(),
                        answers_ref: mp.answers_ref.clone(),
                        idempotency_key: Some(ikey),
                    })),
                });
            }
            Some(b) => {
                let kind_differs = b.kind.to_string() != mp.kind;
                let pack_ref_differs = b.pack_ref.as_str() != mp.pack_ref;
                // Content-aware + ref-aware: the stored ref is the env-relative
                // staged path (rewritten on apply), so a raw string compare
                // against the manifest-relative ref would always differ.
                // Compare the staged file's bytes to the manifest source AND
                // verify the binding's `answers_ref` points at the canonical
                // staged path — a prior interrupted apply could have staged the
                // file but failed to persist the ref on the binding, so checking
                // bytes alone would miss that drift. (A manifest that drops
                // answers_ref is left as-is here, matching the prior behaviour.)
                let answers_ref_differs = match &mp.answers_ref {
                    Some(ar) => {
                        let content_outdated = staged_answers_outdated(
                            store,
                            &ctx.env_id,
                            &ctx.manifest_dir,
                            mp.slot,
                            ar,
                        )?;
                        let ref_wrong =
                            b.answers_ref.as_deref() != Some(staged_answers_rel(mp.slot).as_path());
                        content_outdated || ref_wrong
                    }
                    None => false,
                };
                if kind_differs || pack_ref_differs || answers_ref_differs {
                    let desired_hash = hash_json(&json!({
                        "slot": mp.slot.to_string(),
                        "kind": mp.kind,
                        "pack_ref": mp.pack_ref,
                        "answers_ref": mp.answers_ref,
                    }));
                    let ikey = derive_idempotency_key(
                        &ctx.env_id,
                        ApplyStepKind::UpdatePackBinding.label(),
                        &mp.slot.to_string(),
                        &desired_hash,
                    );
                    let mut what = Vec::new();
                    if kind_differs {
                        what.push(format!("kind → {}", mp.kind));
                    }
                    if pack_ref_differs {
                        what.push(format!("pack_ref → {}", mp.pack_ref));
                    }
                    if answers_ref_differs {
                        what.push("answers_ref".to_string());
                    }
                    steps.push(ApplyStep {
                        kind: ApplyStepKind::UpdatePackBinding,
                        key: mp.slot.to_string(),
                        action: ApplyAction::Update,
                        detail: what.join(", "),
                        idempotency_key: Some(ikey.clone()),
                        op: StepOp::UpdatePackBinding(Box::new(EnvPackBindingPayload {
                            environment_id: env_id_str.clone(),
                            slot: mp.slot,
                            kind: mp.kind.clone(),
                            pack_ref: mp.pack_ref.clone(),
                            answers_ref: mp.answers_ref.clone(),
                            idempotency_key: Some(ikey),
                        })),
                    });
                } else {
                    steps.push(ApplyStep::no_op(
                        ApplyStepKind::AddPackBinding,
                        mp.slot.to_string(),
                        format!("bound ({}, {})", mp.kind, mp.pack_ref),
                    ));
                }
            }
        }
    }

    // 5. Secrets — always-put: `op secrets get` is not-yet-implemented for
    //    every backend, so values cannot be diffed. The plan says so
    //    explicitly rather than ever claiming a false no-op; when A9 lands a
    //    real `get`, this tightens to write-if-changed with no schema
    //    change. Secrets land before bundles so a just-deployed revision
    //    never serves a request that resolves a missing secret.
    for s in &ctx.manifest.secrets {
        // A paste-sourced secret already in the store needs no put step
        // (store-as-source-of-truth). A missing-input secret still emits an
        // undiffable put step for plan visibility — it never reaches execute
        // because the mutating path aborts on missing inputs first, exactly
        // as for an unset env var.
        if ctx.store_satisfied_paths.contains(&s.path) {
            continue;
        }
        // Deliberately NO deterministic idempotency key: an always-put is
        // by definition a NEW write (values cannot be diffed until A9), so
        // a value-insensitive key would stamp two semantically different
        // writes (e.g. a secret rotation under the same env var) with the
        // same key — conflating audit records and wrongly replaying under
        // any future same-key dedupe layer (A8 same-key-different-body
        // conflict rule). `secrets::put` mints a fresh per-invocation key
        // instead (second exception alongside deploy's per-revision
        // cut-over key).
        let detail = match &s.from_env {
            None => "pasted (cannot diff until A9)".to_string(),
            Some(_) if ctx.prompted_paths.contains(&s.path) => {
                "prompted (cannot diff until A9)".to_string()
            }
            Some(from_env) => format!("from ${from_env} (cannot diff until A9)"),
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
        let is_multi = rb.spec.revisions.is_some();
        let existing = ctx.env.as_ref().and_then(|e| {
            e.bundles.iter().find(|d| {
                d.bundle_id.as_str() == rb.spec.bundle_id && d.customer_id == rb.customer_id
            })
        });

        // Helper: the primary digest for single-revision entries (first
        // and only element).
        let primary_digest = || rb.revisions[0].digest.clone();

        match existing {
            None if is_multi => {
                let digests: Vec<String> = rb
                    .revisions
                    .iter()
                    .map(|r| format!("{}@{}", r.spec.name, short_digest(&r.digest)))
                    .collect();
                let detail = format!(
                    "{} revision(s) [{}] → {}",
                    rb.revisions.len(),
                    digests.join(", "),
                    binding_summary(&rb.spec.route_binding.clone().map(into_route_binding))
                );
                steps.push(ApplyStep {
                    kind: ApplyStepKind::DeploySplit,
                    key: rb.spec.bundle_id.clone(),
                    action: ApplyAction::Create,
                    detail,
                    idempotency_key: None,
                    op: deploy_split_op(&env_id_str, rb),
                });
            }
            None => {
                let detail = format!(
                    "{} → {}",
                    short_digest(&primary_digest()),
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
                        expected_digest: primary_digest(),
                    },
                });
            }
            Some(dep) if is_multi => {
                let env = ctx.env.as_ref().expect("existing deployment implies env");
                let converged = split_converged(env, dep.deployment_id, &rb.revisions);
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

                if !converged {
                    let digests: Vec<String> = rb
                        .revisions
                        .iter()
                        .map(|r| format!("{}@{}", r.spec.name, short_digest(&r.digest)))
                        .collect();
                    let detail = format!(
                        "split not converged → re-deploy {} revision(s) [{}]",
                        rb.revisions.len(),
                        digests.join(", ")
                    );
                    steps.push(ApplyStep {
                        kind: ApplyStepKind::DeploySplit,
                        key: rb.spec.bundle_id.clone(),
                        action: ApplyAction::Update,
                        detail,
                        idempotency_key: None,
                        op: deploy_split_op(&env_id_str, rb),
                    });
                }

                // Metadata reconcile. `config_overrides` defers to a converged
                // split (it otherwise rides the next re-split run); revenue_
                // share/status are deployment-level and reconcile independently
                // of the split (a re-split never touches them).
                let diff = BundleMetaDiff {
                    route_binding: binding_differs.then(|| {
                        rb.spec
                            .route_binding
                            .clone()
                            .expect("binding_differs implies manifest binding")
                    }),
                    config_overrides: (overrides_differ && converged)
                        .then(|| rb.spec.config_overrides.clone().expect("overrides_differ")),
                    revenue_share: revenue_share_differs(rb, dep).then(|| {
                        rb.spec
                            .revenue_share
                            .clone()
                            .expect("differs implies manifest")
                    }),
                    status: status_differs(rb, dep).then(|| rb.spec.status.expect("differs")),
                };
                let did_update = !diff.is_noop();
                if let Some(step) = bundle_meta_update_step(
                    &ctx.env_id,
                    &env_id_str,
                    &rb.spec.bundle_id,
                    dep.deployment_id,
                    &desired_binding,
                    diff,
                ) {
                    steps.push(step);
                }

                if converged && !did_update {
                    steps.push(ApplyStep::no_op(
                        ApplyStepKind::DeploySplit,
                        rb.spec.bundle_id.clone(),
                        format!("split converged ({} revision(s))", rb.revisions.len()),
                    ));
                }
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
                let converged = deployment_converged(
                    env,
                    dep.deployment_id,
                    &primary_digest(),
                    rb.spec.bundle_source_uri.as_deref(),
                );
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
                            short_digest(&primary_digest())
                        )
                    } else {
                        format!(
                            "traffic split is not a single 100% entry \
                             → re-deploy reconverges ({})",
                            short_digest(&primary_digest())
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
                            expected_digest: primary_digest(),
                        },
                    });
                }

                // Metadata reconcile. `config_overrides` ride the deploy when
                // re-staging (so they defer here while `needs_deploy`); the
                // binding is applied AFTER the deploy lands; revenue_share/
                // status are deployment-level and reconcile independently of
                // the deploy (a re-deploy never resets them).
                let diff = BundleMetaDiff {
                    route_binding: binding_differs.then(|| {
                        rb.spec
                            .route_binding
                            .clone()
                            .expect("binding_differs implies manifest binding")
                    }),
                    config_overrides: (overrides_differ && !needs_deploy)
                        .then(|| rb.spec.config_overrides.clone().expect("overrides_differ")),
                    revenue_share: revenue_share_differs(rb, dep).then(|| {
                        rb.spec
                            .revenue_share
                            .clone()
                            .expect("differs implies manifest")
                    }),
                    status: status_differs(rb, dep).then(|| rb.spec.status.expect("differs")),
                };
                let did_update = !diff.is_noop();
                if let Some(step) = bundle_meta_update_step(
                    &ctx.env_id,
                    &env_id_str,
                    &rb.spec.bundle_id,
                    dep.deployment_id,
                    &desired_binding,
                    diff,
                ) {
                    steps.push(step);
                }

                if !needs_deploy && !did_update {
                    steps.push(ApplyStep::no_op(
                        ApplyStepKind::DeployBundle,
                        rb.spec.bundle_id.clone(),
                        format!("digest match ({})", short_digest(&primary_digest())),
                    ));
                }
            }
        }
    }

    // 8. Extensions — N-per-env open namespace, keyed by (kind.path(), instance_id).
    for mx in &ctx.manifest.extensions {
        let kind_path = greentic_deploy_spec::PackDescriptor::try_new(&mx.kind)
            .expect("validate_shape already validated kind")
            .path()
            .to_string();
        let ext_key = format!(
            "{}{}",
            kind_path,
            mx.instance_id
                .as_ref()
                .map(|i| format!("/{i}"))
                .unwrap_or_default()
        );
        let existing = ctx.env.as_ref().and_then(|e| {
            e.extensions
                .iter()
                .find(|b| b.kind.path() == kind_path && b.instance_id == mx.instance_id)
        });
        match existing {
            None => {
                let desired_hash = hash_json(&json!({
                    "kind": mx.kind,
                    "pack_ref": mx.pack_ref,
                    "instance_id": mx.instance_id,
                    "answers_ref": mx.answers_ref,
                }));
                let ikey = derive_idempotency_key(
                    &ctx.env_id,
                    ApplyStepKind::AddExtension.label(),
                    &ext_key,
                    &desired_hash,
                );
                steps.push(ApplyStep {
                    kind: ApplyStepKind::AddExtension,
                    key: ext_key,
                    action: ApplyAction::Create,
                    detail: format!("{} ({})", mx.kind, mx.pack_ref),
                    idempotency_key: Some(ikey.clone()),
                    op: StepOp::AddExtension(Box::new(ExtensionBindingPayload {
                        environment_id: env_id_str.clone(),
                        kind: mx.kind.clone(),
                        pack_ref: mx.pack_ref.clone(),
                        instance_id: mx.instance_id.clone(),
                        answers_ref: mx.answers_ref.clone(),
                        idempotency_key: Some(ikey),
                    })),
                });
            }
            Some(b) => {
                let kind_differs = b.kind.to_string() != mx.kind;
                let pack_ref_differs = b.pack_ref.as_str() != mx.pack_ref;
                let answers_ref_differs = mx
                    .answers_ref
                    .as_ref()
                    .is_some_and(|ar| b.answers_ref.as_ref() != Some(ar));
                if kind_differs || pack_ref_differs || answers_ref_differs {
                    let desired_hash = hash_json(&json!({
                        "kind": mx.kind,
                        "pack_ref": mx.pack_ref,
                        "instance_id": mx.instance_id,
                        "answers_ref": mx.answers_ref,
                    }));
                    let ikey = derive_idempotency_key(
                        &ctx.env_id,
                        ApplyStepKind::UpdateExtension.label(),
                        &ext_key,
                        &desired_hash,
                    );
                    let mut what = Vec::new();
                    if kind_differs {
                        what.push(format!("kind → {}", mx.kind));
                    }
                    if pack_ref_differs {
                        what.push(format!("pack_ref → {}", mx.pack_ref));
                    }
                    if answers_ref_differs {
                        what.push("answers_ref".to_string());
                    }
                    steps.push(ApplyStep {
                        kind: ApplyStepKind::UpdateExtension,
                        key: ext_key,
                        action: ApplyAction::Update,
                        detail: what.join(", "),
                        idempotency_key: Some(ikey.clone()),
                        op: StepOp::UpdateExtension(Box::new(ExtensionBindingPayload {
                            environment_id: env_id_str.clone(),
                            kind: mx.kind.clone(),
                            pack_ref: mx.pack_ref.clone(),
                            instance_id: mx.instance_id.clone(),
                            answers_ref: mx.answers_ref.clone(),
                            idempotency_key: Some(ikey),
                        })),
                    });
                } else {
                    steps.push(ApplyStep::no_op(
                        ApplyStepKind::AddExtension,
                        ext_key,
                        format!("bound ({}, {})", mx.kind, mx.pack_ref),
                    ));
                }
            }
        }
    }

    // 9. Endpoints (add → link → welcome-flow, per endpoint in manifest order).
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
                        // The env-manifest doesn't carry a webhook secret ref;
                        // a manifest-applied telegram endpoint auto-mints via the
                        // local dev-store sink (env apply is local-only).
                        webhook_secret_ref: None,
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
        for rr in &rb.revisions {
            ensure_artifact_unchanged(&rr.resolved_path, &rr.digest)?;
        }
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
            StepOp::UpdateHostConfig(payload) => {
                super::config::set(store, &exec_flags, Some((**payload).clone())).map(|_| ())
            }
            StepOp::AddPackBinding(payload) => {
                let payload = stage_binding_answers(store, ctx, (**payload).clone())?;
                super::env_packs::add(store, &exec_flags, Some(payload)).map(|_| ())
            }
            StepOp::UpdatePackBinding(payload) => {
                let payload = stage_binding_answers(store, ctx, (**payload).clone())?;
                super::env_packs::update(store, &exec_flags, Some(payload)).map(|_| ())
            }
            StepOp::AddExtension(payload) => {
                super::extensions::add(store, &exec_flags, Some((**payload).clone())).map(|_| ())
            }
            StepOp::UpdateExtension(payload) => {
                super::extensions::update(store, &exec_flags, Some((**payload).clone())).map(|_| ())
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
            StepOp::DeploySplit { .. } => {
                execute_deploy_split(store, &exec_flags, &step.op)?;
                Ok(())
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

    // Host-config fields.
    {
        let me = &ctx.manifest.environment;
        if let Some(name) = &me.name {
            checked += 1;
            if *name != env.name {
                failures.push(format!("name is `{}`, expected `{name}`", env.name));
            }
        }
        if let Some(region) = &me.region {
            checked += 1;
            if env.host_config.region.as_deref() != Some(region.as_str()) {
                failures.push(format!(
                    "region is `{:?}`, expected `{region}`",
                    env.host_config.region
                ));
            }
        }
        if let Some(tenant_org_id) = &me.tenant_org_id {
            checked += 1;
            if env.host_config.tenant_org_id.as_deref() != Some(tenant_org_id.as_str()) {
                failures.push(format!(
                    "tenant_org_id is `{:?}`, expected `{tenant_org_id}`",
                    env.host_config.tenant_org_id
                ));
            }
        }
        if let Some(listen_addr) = &me.listen_addr {
            checked += 1;
            let parsed: std::net::SocketAddr = listen_addr
                .parse()
                .expect("validate_shape already validated listen_addr");
            if env.host_config.listen_addr != Some(parsed) {
                failures.push(format!(
                    "listen_addr is `{:?}`, expected `{parsed}`",
                    env.host_config.listen_addr
                ));
            }
        }
        if let Some(gui_enabled) = me.gui_enabled {
            checked += 1;
            if env.host_config.gui_enabled != Some(gui_enabled) {
                failures.push(format!(
                    "gui_enabled is `{:?}`, expected `{gui_enabled}`",
                    env.host_config.gui_enabled
                ));
            }
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

    // Env-packs.
    for mp in &ctx.manifest.packs {
        checked += 1;
        let Some(b) = env.pack_for_slot(mp.slot) else {
            failures.push(format!("pack slot `{}` is not bound", mp.slot));
            continue;
        };
        if b.kind.to_string() != mp.kind {
            failures.push(format!(
                "pack slot `{}`: kind is `{}`, expected `{}`",
                mp.slot, b.kind, mp.kind
            ));
        }
        if b.pack_ref.as_str() != mp.pack_ref {
            failures.push(format!(
                "pack slot `{}`: pack_ref is `{}`, expected `{}`",
                mp.slot,
                b.pack_ref.as_str(),
                mp.pack_ref
            ));
        }
        if mp.answers_ref.is_some()
            && b.answers_ref.as_deref() != Some(staged_answers_rel(mp.slot).as_path())
        {
            failures.push(format!(
                "pack slot `{}`: answers_ref is `{:?}`, expected `{:?}`",
                mp.slot,
                b.answers_ref,
                staged_answers_rel(mp.slot)
            ));
        }
    }

    // Extensions.
    for mx in &ctx.manifest.extensions {
        checked += 1;
        let kind_path = greentic_deploy_spec::PackDescriptor::try_new(&mx.kind)
            .expect("validate_shape already validated kind")
            .path()
            .to_string();
        let ext_key = format!(
            "{}{}",
            kind_path,
            mx.instance_id
                .as_ref()
                .map(|i| format!("/{i}"))
                .unwrap_or_default()
        );
        let Some(b) = env
            .extensions
            .iter()
            .find(|b| b.kind.path() == kind_path && b.instance_id == mx.instance_id)
        else {
            failures.push(format!("extension `{ext_key}` is not bound"));
            continue;
        };
        if b.kind.to_string() != mx.kind {
            failures.push(format!(
                "extension `{ext_key}`: kind is `{}`, expected `{}`",
                b.kind, mx.kind
            ));
        }
        if b.pack_ref.as_str() != mx.pack_ref {
            failures.push(format!(
                "extension `{ext_key}`: pack_ref is `{}`, expected `{}`",
                b.pack_ref.as_str(),
                mx.pack_ref
            ));
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
        let is_multi = rb.spec.revisions.is_some();
        if is_multi {
            if !split_converged(&env, dep.deployment_id, &rb.revisions) {
                failures.push(format!(
                    "bundle `{}`: traffic split not converged ({} revision(s) expected)",
                    rb.spec.bundle_id,
                    rb.revisions.len()
                ));
            }
        } else {
            let primary_digest = &rb.revisions[0].digest;
            if !deployment_converged(
                &env,
                dep.deployment_id,
                primary_digest,
                rb.spec.bundle_source_uri.as_deref(),
            ) {
                failures.push(format!(
                    "bundle `{}`: live revision digest is `{}`, expected `{}`",
                    rb.spec.bundle_id,
                    live_revision_digest(&env, dep.deployment_id).unwrap_or("none"),
                    primary_digest
                ));
            }
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
        // revenue_share (G2) is threaded into the create path AND reconciled
        // for existing deployments, so it is correct after a single apply —
        // assert it whenever declared.
        if let Some(shares) = &rb.spec.revenue_share
            && convert_revenue_share(shares) != dep.revenue_share
        {
            failures.push(format!(
                "bundle `{}`: revenue_share differs from the manifest",
                rb.spec.bundle_id
            ));
        }
        // status (G3) is reconcile-only against an EXISTING deployment. A
        // deployment created during THIS apply is born `active`, so a declared
        // non-`active` status converges on the next apply — don't fail verify
        // for it here. Assert only when the deployment pre-dated this apply.
        let existed_pre_apply = ctx.env.as_ref().is_some_and(|e| {
            e.bundles
                .iter()
                .any(|d| d.bundle_id == dep.bundle_id && d.customer_id == dep.customer_id)
        });
        if let Some(status) = rb.spec.status
            && existed_pre_apply
            && status != dep.status
        {
            failures.push(format!(
                "bundle `{}`: status is `{:?}`, expected `{status:?}`",
                rb.spec.bundle_id, dep.status
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

/// True when the manifest declares a revenue-share that differs from the live
/// deployment's split. Absent in the manifest = "leave untouched" = no diff.
fn revenue_share_differs(
    rb: &ResolvedBundle,
    dep: &greentic_deploy_spec::BundleDeployment,
) -> bool {
    rb.spec
        .revenue_share
        .as_ref()
        .is_some_and(|s| convert_revenue_share(s) != dep.revenue_share)
}

/// True when the manifest declares a status that differs from the live
/// deployment's status. Absent in the manifest = "leave untouched" = no diff.
fn status_differs(rb: &ResolvedBundle, dep: &greentic_deploy_spec::BundleDeployment) -> bool {
    rb.spec.status.is_some_and(|s| s != dep.status)
}

/// Desired `bundles update` mutations for one bundle entry, derived against a
/// live deployment. Each `Some` field is applied; an all-`None` set means no
/// update step is needed.
struct BundleMetaDiff {
    /// Set when the manifest route binding differs from the live binding.
    route_binding: Option<RouteBindingPayload>,
    /// Set when overrides differ AND the deploy/stage gate allows applying
    /// them this run (they otherwise ride the deploy, or defer one apply).
    config_overrides: Option<BTreeMap<String, BTreeMap<String, Value>>>,
    /// Set when the manifest revenue-share differs from the live split.
    revenue_share: Option<Vec<RevenueShareEntryPayload>>,
    /// Set when the manifest status differs from the live status.
    status: Option<BundleDeploymentStatus>,
}

impl BundleMetaDiff {
    fn is_noop(&self) -> bool {
        self.route_binding.is_none()
            && self.config_overrides.is_none()
            && self.revenue_share.is_none()
            && self.status.is_none()
    }
}

/// Build a `bundles update` step from the desired metadata mutations, or
/// `None` when nothing differs. Centralizes the idempotency-key derivation,
/// the human `detail` string, and the payload so both reconcile arms
/// (single- and multi-revision) share one construction.
fn bundle_meta_update_step(
    env_id: &EnvId,
    env_id_str: &str,
    bundle_id: &str,
    deployment_id: DeploymentId,
    desired_binding: &Option<RouteBinding>,
    diff: BundleMetaDiff,
) -> Option<ApplyStep> {
    if diff.is_noop() {
        return None;
    }
    // Hash the revenue-share as ordered (party, bps) pairs (the payload type
    // isn't directly hashable through `hash_json` without this projection).
    let revenue_share_hash = diff.revenue_share.as_ref().map(|s| {
        s.iter()
            .map(|e| (e.party_id.clone(), e.basis_points))
            .collect::<Vec<_>>()
    });
    let desired_hash = hash_json(&json!({
        "route_binding": diff.route_binding,
        "config_overrides": diff.config_overrides,
        "revenue_share": revenue_share_hash,
        "status": diff.status,
    }));
    let ikey = derive_idempotency_key(
        env_id,
        ApplyStepKind::UpdateBundle.label(),
        bundle_id,
        &desired_hash,
    );
    let mut what = Vec::new();
    if diff.route_binding.is_some() {
        what.push(format!("binding → {}", binding_summary(desired_binding)));
    }
    if diff.config_overrides.is_some() {
        what.push("config_overrides".to_string());
    }
    if diff.revenue_share.is_some() {
        what.push("revenue_share".to_string());
    }
    if let Some(s) = diff.status {
        what.push(format!("status → {s:?}"));
    }
    Some(ApplyStep {
        kind: ApplyStepKind::UpdateBundle,
        key: bundle_id.to_string(),
        action: ApplyAction::Update,
        detail: what.join(", "),
        idempotency_key: Some(ikey.clone()),
        op: StepOp::BundleUpdate(Box::new(BundleUpdatePayload {
            environment_id: env_id_str.to_string(),
            deployment_id: deployment_id.to_string(),
            status: diff.status,
            route_binding: diff.route_binding,
            revenue_share: diff.revenue_share,
            config_overrides: diff.config_overrides,
            idempotency_key: Some(ikey),
        })),
    })
}

/// Canonical in-store location for a pack binding's staged answers file —
/// `env-packs/<slot>/answers.json`, relative to the env dir. Matches the
/// path convention the reconcile resolver ([`super::env::load_render_answers`])
/// expects.
fn staged_answers_rel(slot: CapabilitySlot) -> PathBuf {
    PathBuf::from("env-packs")
        .join(slot.to_string())
        .join("answers.json")
}

/// Resolve a binding's `answers_ref` against the manifest dir (the schema
/// contract: paths are manifest-relative).
fn resolve_answers_src(manifest_dir: &Path, manifest_ref: &Path) -> PathBuf {
    if manifest_ref.is_absolute() {
        manifest_ref.to_path_buf()
    } else {
        manifest_dir.join(manifest_ref)
    }
}

/// True when the staged answers file is missing or its content differs from
/// the manifest source — i.e. apply must (re)stage it. Identical content
/// re-applies as a no-op, so apply stays idempotent.
fn staged_answers_outdated(
    store: &LocalFsStore,
    env_id: &EnvId,
    manifest_dir: &Path,
    slot: CapabilitySlot,
    manifest_ref: &Path,
) -> Result<bool, OpError> {
    let src = resolve_answers_src(manifest_dir, manifest_ref);
    let staged = store.env_dir(env_id)?.join(staged_answers_rel(slot));
    let src_bytes = std::fs::read(&src).map_err(|source| OpError::Io {
        path: src.clone(),
        source,
    })?;
    match std::fs::read(&staged) {
        Ok(staged_bytes) => Ok(staged_bytes != src_bytes),
        Err(_) => Ok(true),
    }
}

/// Copy a binding's manifest-relative `answers_ref` into the env store at the
/// canonical path and return that env-relative path. Apply records the
/// returned ref on the binding so reconcile — which resolves `answers_ref`
/// against the env dir — finds the file. Skips a no-op self-copy when source
/// and destination are already the same file.
fn stage_answers_file(
    store: &LocalFsStore,
    env_id: &EnvId,
    manifest_dir: &Path,
    slot: CapabilitySlot,
    manifest_ref: &Path,
) -> Result<PathBuf, OpError> {
    let src = resolve_answers_src(manifest_dir, manifest_ref);
    let rel = staged_answers_rel(slot);
    let dest = store.env_dir(env_id)?.join(&rel);
    let same_file = dest.exists() && src.canonicalize().ok() == dest.canonicalize().ok();
    if !same_file {
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|source| OpError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        std::fs::copy(&src, &dest).map_err(|source| OpError::Io {
            path: src.clone(),
            source,
        })?;
    }
    Ok(rel)
}

/// Stage a pack binding's answers file (if any) and rewrite the payload's
/// `answers_ref` to the env-relative staged path before it is persisted.
/// Bindings without an answers_ref pass through unchanged.
fn stage_binding_answers(
    store: &LocalFsStore,
    ctx: &ApplyContext,
    mut payload: EnvPackBindingPayload,
) -> Result<EnvPackBindingPayload, OpError> {
    if let Some(manifest_ref) = payload.answers_ref.clone() {
        payload.answers_ref = Some(stage_answers_file(
            store,
            &ctx.env_id,
            &ctx.manifest_dir,
            payload.slot,
            &manifest_ref,
        )?);
    }
    Ok(payload)
}

/// Hash a resolved bundle artifact and, when the manifest pins a `bundle_digest`,
/// fail closed unless the file matches. Returns the computed `sha256:` digest
/// recorded on the revision. `location` labels the bundle (and revision, for a
/// split) in the mismatch error. Applies uniformly to local `bundle_path`
/// artifacts and to ones fetched from a `bundle_source_uri`.
fn resolved_artifact_digest(
    path: &std::path::Path,
    declared: Option<&str>,
    location: &str,
) -> Result<String, OpError> {
    let digest = super::bundle_stage::sha256_file(path).map_err(|source| OpError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if let Some(declared) = declared
        && declared != digest
    {
        return Err(OpError::Conflict(format!(
            "{location}: declared bundle_digest `{declared}` does not match the resolved \
             artifact digest `{digest}`"
        )));
    }
    Ok(digest)
}

/// Build a [`BundleDeployPayload`] from a resolved single-revision bundle.
/// The primary (first) resolved revision supplies the artifact path.
fn deploy_payload(
    env_id: &str,
    rb: &ResolvedBundle,
    route_binding: Option<RouteBindingPayload>,
) -> BundleDeployPayload {
    BundleDeployPayload {
        environment_id: env_id.to_string(),
        bundle_id: rb.spec.bundle_id.clone(),
        customer_id: rb.spec.customer_id.clone(),
        bundle_path: Some(rb.revisions[0].resolved_path.clone()),
        // Single-revision pull ref: a K8s worker fetches the bundle from here
        // at boot; `bundle_path` above supplies the integrity digest.
        bundle_source_uri: rb.spec.bundle_source_uri.clone(),
        // Local manifest-apply path: the artifact at `bundle_path` is staged
        // locally, so no remote pins are threaded.
        remote_pins: None,
        idempotency_key: None,
        config_overrides: rb.spec.config_overrides.clone(),
        route_binding,
        // Threaded into the FRESH-add path; ignored by `deploy` on a
        // re-deploy (the existing split is reconciled via `bundles update`).
        revenue_share: rb.spec.revenue_share.clone(),
    }
}

/// Build a [`StepOp::DeploySplit`] from a resolved multi-revision bundle.
fn deploy_split_op(env_id: &str, rb: &ResolvedBundle) -> StepOp {
    StepOp::DeploySplit {
        env_id: env_id.to_string(),
        bundle_id: rb.spec.bundle_id.clone(),
        customer_id: rb.spec.customer_id.clone(),
        config_overrides: rb.spec.config_overrides.clone(),
        route_binding: rb.spec.route_binding.clone(),
        revenue_share: rb.spec.revenue_share.clone(),
        revisions: rb
            .revisions
            .iter()
            .map(|rr| SplitRevisionEntry {
                name: rr.spec.name.clone(),
                resolved_path: rr.resolved_path.clone(),
                expected_digest: rr.digest.clone(),
                weight_bps: rr.weight_bps,
                drain_seconds: rr.spec.drain_seconds,
                bundle_source_uri: rr.spec.bundle_source_uri.clone(),
            })
            .collect(),
    }
}

/// Execute a multi-revision deploy: add the bundle (if new), stage each
/// revision, warm each, then set the combined traffic split. Takes the
/// whole `StepOp` by reference and destructures the `DeploySplit` variant.
fn execute_deploy_split(store: &LocalFsStore, flags: &OpFlags, op: &StepOp) -> Result<(), OpError> {
    use super::bundles::{BundleAddPayload, BundleSummary};
    use super::revisions::{RevisionStagePayload, RevisionSummary, RevisionTransitionPayload};
    use super::traffic::{TrafficSetEntryPayload, TrafficSetPayload};

    let StepOp::DeploySplit {
        env_id,
        bundle_id,
        customer_id,
        config_overrides,
        route_binding,
        revenue_share,
        revisions: split_revs,
    } = op
    else {
        unreachable!("execute_deploy_split called with non-DeploySplit op");
    };

    let env_id_parsed = EnvId::try_from(env_id.as_str())
        .map_err(|e| OpError::InvalidArgument(format!("environment_id: {e}")))?;
    let resolved_customer =
        super::bundles::resolve_customer_id(&env_id_parsed, customer_id.clone())?;

    let env = store.load(&env_id_parsed)?;
    let existing = env
        .bundles
        .iter()
        .find(|b| b.bundle_id.as_str() == bundle_id.as_str() && b.customer_id == resolved_customer);

    let deployment_id = match existing {
        Some(b) => b.deployment_id.to_string(),
        None => {
            let add_payload = BundleAddPayload {
                environment_id: env_id.clone(),
                bundle_id: bundle_id.clone(),
                customer_id: customer_id.clone(),
                route_binding: route_binding.clone().unwrap_or_default(),
                revenue_share: revenue_share
                    .clone()
                    .unwrap_or_else(super::bundles::default_revenue_share),
                authorization_ref: super::bundles::default_authorization_ref(),
                config_overrides: config_overrides.clone().unwrap_or_default(),
                idempotency_key: None,
            };
            let outcome = super::bundles::add(store, flags, Some(add_payload))?;
            let summary: BundleSummary = serde_json::from_value(outcome.result).map_err(|e| {
                OpError::InvalidArgument(format!("internal: bundle add summary: {e}"))
            })?;
            summary.deployment_id
        }
    };

    // Stage + warm each revision.
    let mut traffic_entries = Vec::with_capacity(split_revs.len());
    for rev in split_revs {
        eprintln!(
            "  split: staging revision `{}` ({})",
            rev.name,
            short_digest(&rev.expected_digest)
        );
        // TOCTOU re-check per revision.
        ensure_artifact_unchanged(&rev.resolved_path, &rev.expected_digest)?;

        let stage_payload = RevisionStagePayload {
            environment_id: env_id.to_string(),
            deployment_id: deployment_id.clone(),
            // Local `--bundle` stage: the store mints the id + key.
            revision_id: None,
            idempotency_key: None,
            bundle_path: Some(rev.resolved_path.clone()),
            bundle_digest: super::revisions::default_bundle_digest(),
            // Pull ref the manifest declared for this revision (`oci://` /
            // `repo://` / `store://`); a K8s worker fetches the bundle from
            // here at boot. `bundle_path` above supplies the integrity digest.
            // `None` = local-serve only.
            bundle_source_uri: rev.bundle_source_uri.clone(),
            pack_list: Vec::new(),
            pack_list_lock_ref: PathBuf::new(),
            config_digest: super::revisions::default_config_digest(),
            signature_sidecar_ref: super::revisions::default_signature_sidecar_ref(),
            drain_seconds: rev
                .drain_seconds
                .unwrap_or_else(super::revisions::default_drain_seconds),
        };
        let stage_outcome = super::revisions::stage(store, flags, Some(stage_payload))?;
        let staged: RevisionSummary =
            serde_json::from_value(stage_outcome.result).map_err(|e| {
                OpError::InvalidArgument(format!("internal: revision stage summary: {e}"))
            })?;

        super::revisions::warm(
            store,
            flags,
            Some(RevisionTransitionPayload {
                environment_id: env_id.to_string(),
                revision_id: staged.revision_id.clone(),
                idempotency_key: None,
            }),
        )?;

        traffic_entries.push(TrafficSetEntryPayload {
            revision_id: staged.revision_id,
            weight_bps: Some(rev.weight_bps),
            weight_percent: None,
        });
    }

    // Set the combined traffic split.
    let ikey = format!(
        "deploy-split:{deployment_id}:{}",
        traffic_entries
            .iter()
            .map(|e| e.revision_id.as_str())
            .collect::<Vec<_>>()
            .join("+")
    );
    super::traffic::set(
        store,
        flags,
        Some(TrafficSetPayload {
            environment_id: env_id.to_string(),
            deployment_id: deployment_id.clone(),
            entries: traffic_entries,
            updated_by: super::traffic::default_updated_by(),
            idempotency_key: ikey,
            authorization_ref: super::traffic::default_authorization_ref(),
        }),
    )?;

    Ok(())
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
pub(super) fn digest_is_real(digest: &str) -> bool {
    digest.starts_with("sha256:") && digest.len() > "sha256:".len() && digest != "sha256:00"
}

/// Strict convergence: the deployment's traffic split has EXACTLY ONE entry
/// at full weight (10,000 bps), that entry's revision exists, carries a real
/// digest, the digest matches `expected_digest`, and `bundle_source_uri`
/// matches (`None` vs `Some` counts as a difference — a K8s worker needs
/// the pull ref to boot). A mixed split (e.g. 60/40 blue-green) or a
/// degenerate placeholder digest is NOT converged.
fn deployment_converged(
    env: &Environment,
    deployment_id: DeploymentId,
    expected_digest: &str,
    expected_source_uri: Option<&str>,
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
        .is_some_and(|r| {
            digest_is_real(&r.bundle_digest)
                && r.bundle_digest == expected_digest
                && r.bundle_source_uri.as_deref() == expected_source_uri
        })
}

/// Multi-revision convergence: the deployment's traffic split is the exact
/// `(digest, weight_bps, bundle_source_uri)` multiset declared by `expected`
/// — every live entry resolves to a real-digest revision, and the live
/// `(digest, weight, source_uri)` bag equals the expected bag.
/// Order-independent (both bags are sorted before comparison) and
/// duplicate-safe: two expected revisions that share the same artifact AND
/// weight require two matching live entries, not one. A false "converged" is
/// the dangerous direction — it would silently skip applying the desired
/// split — so this is multiset equality, not set containment.
fn split_converged(
    env: &Environment,
    deployment_id: DeploymentId,
    expected: &[ResolvedRevision],
) -> bool {
    let Some(split) = env
        .traffic_splits
        .iter()
        .find(|s| s.deployment_id == deployment_id)
    else {
        return false;
    };
    if split.entries.len() != expected.len() {
        return false;
    }
    // Live `(digest, weight_bps, source_uri)` bag. Any entry pointing at a
    // missing or placeholder-digest revision fails convergence outright.
    let mut live_bag: Vec<(&str, u32, Option<&str>)> = Vec::with_capacity(split.entries.len());
    for entry in &split.entries {
        let Some(rev) = env
            .revisions
            .iter()
            .find(|r| r.revision_id == entry.revision_id)
        else {
            return false;
        };
        if !digest_is_real(&rev.bundle_digest) {
            return false;
        }
        live_bag.push((
            rev.bundle_digest.as_str(),
            entry.weight_bps,
            rev.bundle_source_uri.as_deref(),
        ));
    }
    // Expected `(digest, weight_bps, source_uri)` bag.
    let mut expected_bag: Vec<(&str, u32, Option<&str>)> = expected
        .iter()
        .map(|rr| {
            (
                rr.digest.as_str(),
                rr.weight_bps,
                rr.spec.bundle_source_uri.as_deref(),
            )
        })
        .collect();
    // Multiset equality via sort-and-compare (counts already match).
    live_bag.sort_unstable();
    expected_bag.sort_unstable();
    live_bag == expected_bag
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

    #[test]
    fn resolved_artifact_digest_records_computed_when_undeclared() {
        let path = fixture();
        let digest = resolved_artifact_digest(&path, None, "bundle `x`").unwrap();
        assert_eq!(
            digest,
            super::super::bundle_stage::sha256_file(&path).unwrap()
        );
    }

    #[test]
    fn resolved_artifact_digest_passes_when_declared_matches() {
        let path = fixture();
        let real = super::super::bundle_stage::sha256_file(&path).unwrap();
        let digest = resolved_artifact_digest(&path, Some(&real), "bundle `x`").unwrap();
        assert_eq!(digest, real);
    }

    #[test]
    fn resolved_artifact_digest_rejects_declared_mismatch() {
        let path = fixture();
        let err =
            resolved_artifact_digest(&path, Some("sha256:deadbeef"), "bundle `x`").unwrap_err();
        assert_eq!(err.kind(), "conflict");
        assert!(err.to_string().contains("does not match"), "{err}");
    }

    /// Full URI-only apply: no local `bundle_path`, just a `bundle_source_uri`.
    /// Apply fetches the bundle from ghcr, stages it, and records a revision
    /// carrying the OCI pull ref + a real digest a K8s worker boots from.
    /// Ignored by default (network + ghcr reachability).
    #[test]
    #[ignore = "network: applies a URI-only manifest that pulls from ghcr"]
    fn uri_only_apply_pulls_and_records_a_pullable_revision() {
        const URI: &str = "oci://ghcr.io/greenticai/greentic-demo-bundles/webchat-bot:v1";
        let (dir, store) = seeded_store();
        let manifest = serde_json::json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{
                "bundle_id": "remote",
                "bundle_source_uri": URI
            }]
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        let outcome = run_apply(&store, &manifest_path).expect("uri-only apply succeeds");
        assert_eq!(
            outcome.result["missing"].as_array().unwrap().len(),
            0,
            "no missing inputs: {}",
            outcome.result
        );
        let env = load_local(&store);
        assert_eq!(env.bundles.len(), 1);
        let dep = &env.bundles[0];
        let digest = live_revision_digest(&env, dep.deployment_id).expect("live revision");
        assert!(
            digest.starts_with("sha256:") && digest != "sha256:00",
            "real digest recorded: {digest}"
        );
        let rev = env
            .revisions
            .iter()
            .find(|r| r.deployment_id == dep.deployment_id)
            .expect("revision recorded");
        assert_eq!(
            rev.bundle_source_uri.as_deref(),
            Some(URI),
            "K8s worker pull ref recorded on the revision"
        );
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

    // --- G2/G3: revenue_share + status ---

    /// Minimal single-revision manifest with no binding/endpoints — the base
    /// for the metadata-reconcile tests.
    fn plain_bundle_manifest() -> Value {
        json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{"bundle_id": "quickstart", "bundle_path": fixture()}]
        })
    }

    #[test]
    fn status_reconciles_against_existing_deployment() {
        let (dir, store) = seeded_store();
        let base = plain_bundle_manifest();
        let base_path = write_manifest(dir.path(), &base);
        run_apply(&store, &base_path).expect("first apply");
        assert_eq!(
            load_local(&store).bundles[0].status,
            BundleDeploymentStatus::Active
        );

        // Re-apply with status: paused → one update-bundle, no re-stage.
        let mut paused = base.clone();
        paused["bundles"][0]["status"] = json!("paused");
        let paused_path = write_manifest(dir.path(), &paused);
        let plan = run_dry(&store, &paused_path).expect("dry-run");
        let actions = step_actions(&plan.result);
        assert!(
            actions.contains(&("update-bundle".to_string(), "update".to_string())),
            "status change must plan an update-bundle: {actions:?}"
        );
        assert!(
            actions
                .iter()
                .all(|(k, a)| k != "deploy-bundle" || a == "no-op"),
            "status change must not re-stage: {actions:?}"
        );

        run_apply(&store, &paused_path).expect("apply pause");
        assert_eq!(
            load_local(&store).bundles[0].status,
            BundleDeploymentStatus::Paused
        );

        // Idempotent: re-applying the paused manifest changes nothing.
        let plan2 = run_dry(&store, &paused_path).expect("dry-run 2");
        assert_eq!(plan2.result["changed"], 0, "{}", plan2.result);
    }

    #[test]
    fn revenue_share_reconciles_against_existing_deployment() {
        let (dir, store) = seeded_store();
        let base = plain_bundle_manifest();
        let base_path = write_manifest(dir.path(), &base);
        run_apply(&store, &base_path).expect("first apply");
        // Default split = greentic@10000.
        assert_eq!(load_local(&store).bundles[0].revenue_share.len(), 1);

        let mut split = base.clone();
        split["bundles"][0]["revenue_share"] = json!([
            {"party_id": "greentic", "basis_points": 7000},
            {"party_id": "partner", "basis_points": 3000}
        ]);
        let split_path = write_manifest(dir.path(), &split);
        let plan = run_dry(&store, &split_path).expect("dry-run");
        assert!(
            step_actions(&plan.result)
                .contains(&("update-bundle".to_string(), "update".to_string())),
            "revenue_share change must plan an update-bundle"
        );

        run_apply(&store, &split_path).expect("apply revenue split");
        let env = load_local(&store);
        let shares = &env.bundles[0].revenue_share;
        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0].party_id.as_str(), "greentic");
        assert_eq!(shares[0].basis_points, 7000);
        assert_eq!(shares[1].party_id.as_str(), "partner");
        assert_eq!(shares[1].basis_points, 3000);

        // Idempotent.
        let plan2 = run_dry(&store, &split_path).expect("dry-run 2");
        assert_eq!(plan2.result["changed"], 0, "{}", plan2.result);
    }

    #[test]
    fn revenue_share_threaded_into_fresh_deploy_single_apply() {
        let (dir, store) = seeded_store();
        let mut manifest = plain_bundle_manifest();
        manifest["bundles"][0]["revenue_share"] = json!([
            {"party_id": "greentic", "basis_points": 6000},
            {"party_id": "partner", "basis_points": 4000}
        ]);
        let p = write_manifest(dir.path(), &manifest);
        // A SINGLE apply must converge — verify asserts revenue_share, so this
        // proves it is threaded into the create path (not deferred).
        run_apply(&store, &p).expect("fresh apply with revenue_share must verify");
        let shares = &load_local(&store).bundles[0].revenue_share;
        assert_eq!(shares.len(), 2);
        assert_eq!(shares[1].party_id.as_str(), "partner");
        assert_eq!(shares[1].basis_points, 4000);
        assert_eq!(run_dry(&store, &p).expect("dry").result["changed"], 0);
    }

    #[test]
    fn status_on_fresh_create_defers_one_apply_without_failing_verify() {
        let (dir, store) = seeded_store();
        let mut manifest = plain_bundle_manifest();
        manifest["bundles"][0]["status"] = json!("paused");
        let p = write_manifest(dir.path(), &manifest);
        // First apply creates the deployment (born `active`); verify must NOT
        // fail for the not-yet-applied `paused` status (reconcile-only).
        run_apply(&store, &p).expect("fresh apply with status must not fail verify");
        assert_eq!(
            load_local(&store).bundles[0].status,
            BundleDeploymentStatus::Active
        );
        // Second apply: the deployment now pre-dates the apply → status
        // reconciles to paused, single-apply from here.
        run_apply(&store, &p).expect("second apply pauses");
        assert_eq!(
            load_local(&store).bundles[0].status,
            BundleDeploymentStatus::Paused
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
                    webhook_secret_ref: None,
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
                webhook_secret_ref: None,
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
    fn nonexistent_nonlocal_env_gives_clear_error() {
        // `env apply` reconciles an existing named env but does not bootstrap
        // one (only `local` is auto-created). Applying a manifest for a
        // not-yet-created named env must fail at plan time with a clear message
        // pointing the user at `op env create <id>`.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {
                "id": "prod",
                "name": "Production",
                "region": "us-east-1",
                "tenant_org_id": "org-42",
            }
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        let err = run_apply(&store, &manifest_path).unwrap_err();
        match err {
            OpError::NotFound(msg) => {
                assert!(
                    msg.contains("not found")
                        && msg.contains("op env create prod")
                        && msg.contains("does not create one"),
                    "got: {msg}"
                );
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
                bundle_source_uri: None,
                remote_pins: None,
                idempotency_key: None,
                config_overrides: None,
                route_binding: None,
                revenue_share: None,
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

    // --- split_converged is multiset equality, not set containment ---

    /// Build a `ResolvedRevision` with the given digest + weight
    /// (`bundle_source_uri` defaults to `None`).
    fn resolved_rev(name: &str, digest: &str, weight_bps: u32) -> ResolvedRevision {
        ResolvedRevision {
            spec: ManifestRevision {
                name: name.to_string(),
                bundle_path: PathBuf::from(format!("{name}.gtbundle")),
                weight_percent: None,
                weight_bps: Some(weight_bps),
                drain_seconds: None,
                abort_metrics: Vec::new(),
                bundle_source_uri: None,
                bundle_digest: None,
            },
            resolved_path: PathBuf::from(format!("{name}.gtbundle")),
            digest: digest.to_string(),
            weight_bps,
        }
    }

    /// Seed an env with a two-entry split over two revisions, returning the
    /// env and its deployment id. Each `(digest, weight_bps)` is applied to a
    /// distinct revision.
    fn env_with_two_entry_split(live: [(&str, u32); 2]) -> (Environment, DeploymentId) {
        use greentic_deploy_spec::TrafficSplitEntry;
        let mut env = make_env("local");
        let dep = make_bundle_deployment("local", "quickstart");
        let dep_id = dep.deployment_id;
        let mut rev1 = make_revision("local", "quickstart", &dep_id, 1, RevisionLifecycle::Ready);
        rev1.bundle_digest = live[0].0.to_string();
        let mut rev2 = make_revision("local", "quickstart", &dep_id, 2, RevisionLifecycle::Ready);
        rev2.bundle_digest = live[1].0.to_string();
        let mut split =
            make_traffic_split("local", "quickstart", &dep_id, &rev1.revision_id, "seed");
        split.entries[0].weight_bps = live[0].1;
        split.entries.push(TrafficSplitEntry {
            revision_id: rev2.revision_id,
            weight_bps: live[1].1,
        });
        env.bundles.push(dep);
        env.revisions.push(rev1);
        env.revisions.push(rev2);
        env.traffic_splits.push(split);
        (env, dep_id)
    }

    #[test]
    fn split_converged_matches_exact_multiset() {
        let (env, dep_id) =
            env_with_two_entry_split([("sha256:aaaa11", 5_000), ("sha256:bbbb22", 5_000)]);
        let expected = [
            resolved_rev("a", "sha256:aaaa11", 5_000),
            resolved_rev("b", "sha256:bbbb22", 5_000),
        ];
        assert!(
            split_converged(&env, dep_id, &expected),
            "identical (digest, weight) bag must converge"
        );
        // Order-independence: same bag, swapped expected order.
        let swapped = [
            resolved_rev("b", "sha256:bbbb22", 5_000),
            resolved_rev("a", "sha256:aaaa11", 5_000),
        ];
        assert!(split_converged(&env, dep_id, &swapped));
    }

    #[test]
    fn split_converged_rejects_duplicate_digest_mismatch() {
        // Live bag has TWO distinct digests; expected names the SAME digest
        // twice. A set-containment check (the old `.any()`) would falsely
        // report convergence; a multiset check must reject it — otherwise the
        // desired split is silently never applied.
        let (env, dep_id) =
            env_with_two_entry_split([("sha256:aaaa11", 5_000), ("sha256:bbbb22", 5_000)]);
        let expected = [
            resolved_rev("a", "sha256:aaaa11", 5_000),
            resolved_rev("a-dup", "sha256:aaaa11", 5_000),
        ];
        assert!(
            !split_converged(&env, dep_id, &expected),
            "duplicate-digest expected bag must NOT match a two-distinct-digest live split"
        );
    }

    #[test]
    fn split_converged_rejects_weight_mismatch() {
        let (env, dep_id) =
            env_with_two_entry_split([("sha256:aaaa11", 6_000), ("sha256:bbbb22", 4_000)]);
        let expected = [
            resolved_rev("a", "sha256:aaaa11", 5_000),
            resolved_rev("b", "sha256:bbbb22", 5_000),
        ];
        assert!(
            !split_converged(&env, dep_id, &expected),
            "same digests but different weights must not converge"
        );
    }

    #[test]
    fn split_converged_rejects_placeholder_digest() {
        // A live revision still carrying the staging placeholder digest is
        // not a real deploy — convergence must fail.
        let (env, dep_id) =
            env_with_two_entry_split([("sha256:00", 5_000), ("sha256:bbbb22", 5_000)]);
        let expected = [
            resolved_rev("a", "sha256:00", 5_000),
            resolved_rev("b", "sha256:bbbb22", 5_000),
        ];
        assert!(
            !split_converged(&env, dep_id, &expected),
            "placeholder live digest must not be treated as converged"
        );
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
            &BTreeMap::new(),
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

    // --- paste-sourced secrets (manifest `from_env` absent) -----------------

    /// A paste-sourced secret entry: no `from_env`, value supplied out of band.
    fn paste_secrets_manifest() -> Value {
        json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "secrets": [{"path": SECRET_PATH}]
        })
    }

    fn dev_store_value(dir: &Path) -> Vec<u8> {
        let store_path = dir
            .join("local")
            .join(super::super::secrets::DEV_STORE_RELATIVE);
        dev_store_read(&store_path, &format!("secrets://local/{SECRET_PATH}"))
    }

    #[test]
    fn paste_secret_prefilled_value_is_put_and_plan_says_pasted() {
        // The wizard's hand-off: a pre-collected value, no env var, no prompt.
        let (dir, store) = seeded_store_with_dev_secrets();
        let manifest_path = write_manifest(dir.path(), &paste_secrets_manifest());
        let flags = OpFlags {
            schema_only: false,
            answers: Some(manifest_path.clone()),
        };
        let mut prefilled = BTreeMap::new();
        prefilled.insert(
            SECRET_PATH.to_string(),
            SecretValue::from("tok-pasted-42".to_string()),
        );
        let outcome = apply_with_lookups(
            &store,
            &flags,
            ApplyOptions {
                mode: ApplyMode::Apply,
                non_interactive: true,
                prefilled_secrets: prefilled,
                ..ApplyOptions::default()
            },
            &|_| None,
            None,
        )
        .expect("prefilled paste apply succeeds");

        let envelope = serde_json::to_string(&outcome).unwrap();
        assert!(!envelope.contains("tok-pasted-42"), "{envelope}");
        let steps = outcome.result["steps"].as_array().unwrap();
        let put = steps.iter().find(|s| s["kind"] == "put-secret").unwrap();
        assert_eq!(put["detail"], "pasted (cannot diff until A9)");
        assert!(outcome.result["missing"].as_array().unwrap().is_empty());
        assert_eq!(dev_store_value(dir.path()), b"tok-pasted-42".to_vec());
    }

    #[test]
    fn paste_secret_already_in_store_is_a_noop() {
        // Store-as-source-of-truth: with the value already present, a re-apply
        // that can't re-collect it (no prefill, no prompter) is satisfied —
        // no put step, no missing input, value untouched.
        let (dir, store) = seeded_store_with_dev_secrets();
        let manifest_path = write_manifest(dir.path(), &paste_secrets_manifest());
        // Seed via a first prefilled apply.
        let mut prefilled = BTreeMap::new();
        prefilled.insert(
            SECRET_PATH.to_string(),
            SecretValue::from("tok-stored".to_string()),
        );
        let flags = OpFlags {
            schema_only: false,
            answers: Some(manifest_path.clone()),
        };
        apply_with_lookups(
            &store,
            &flags,
            ApplyOptions {
                mode: ApplyMode::Apply,
                non_interactive: true,
                prefilled_secrets: prefilled,
                ..ApplyOptions::default()
            },
            &|_| None,
            None,
        )
        .expect("seed apply");

        // Second apply: no prefill, no prompter, non-interactive.
        let outcome = run_with_lookup(&store, &manifest_path, ApplyMode::Apply, &|_| None)
            .expect("re-apply is a no-op, not a missing-input failure");
        let steps = outcome.result["steps"].as_array().unwrap();
        assert!(
            !steps.iter().any(|s| s["kind"] == "put-secret"),
            "an already-stored paste secret needs no put step: {steps:?}"
        );
        assert!(outcome.result["missing"].as_array().unwrap().is_empty());
        assert_eq!(dev_store_value(dir.path()), b"tok-stored".to_vec());
    }

    #[test]
    fn paste_secret_missing_when_absent_and_non_interactive() {
        // No prefill, not in the store, no prompter → reported missing with a
        // `paste` source (not an env var), and apply aborts before mutation.
        let (dir, store) = seeded_store_with_dev_secrets();
        let manifest_path = write_manifest(dir.path(), &paste_secrets_manifest());
        let err = run_with_lookup(&store, &manifest_path, ApplyMode::Apply, &|_| None).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("1 missing input(s)"), "{msg}");
        assert!(msg.contains("paste"), "names the paste source: {msg}");
        assert!(msg.contains(SECRET_PATH), "{msg}");
        assert!(!dir.path().join("local/audit/events.jsonl").exists());
    }

    #[test]
    fn paste_secret_prompts_with_value_wording() {
        // Interactive, no prefill, not in store → masked prompt; the prompter
        // receives an empty `from_env` (paste wording) and the value is put.
        let (dir, store) = seeded_store_with_dev_secrets();
        let manifest_path = write_manifest(dir.path(), &paste_secrets_manifest());
        let prompter = |path: &str, from_env: &str| {
            assert_eq!(path, SECRET_PATH);
            assert_eq!(from_env, "", "paste secrets prompt with an empty from_env");
            Some("tok-typed".to_string())
        };
        let outcome = run_with_lookup_and_prompter(
            &store,
            &manifest_path,
            ApplyMode::Apply,
            &|_| None,
            Some(&prompter),
        )
        .expect("paste prompt apply succeeds");
        let steps = outcome.result["steps"].as_array().unwrap();
        let put = steps.iter().find(|s| s["kind"] == "put-secret").unwrap();
        assert_eq!(put["detail"], "pasted (cannot diff until A9)");
        assert_eq!(dev_store_value(dir.path()), b"tok-typed".to_vec());
    }

    #[test]
    fn paste_secret_empty_prefilled_is_treated_as_missing() {
        // A prefilled value that is empty must NOT slip through as resolved
        // (it would only be rejected by `secrets::put` at execute, after
        // earlier steps mutated state). Like the env/prompt branches, an empty
        // prefilled value falls through to the missing-input report.
        let (dir, store) = seeded_store_with_dev_secrets();
        let manifest_path = write_manifest(dir.path(), &paste_secrets_manifest());
        let flags = OpFlags {
            schema_only: false,
            answers: Some(manifest_path.clone()),
        };
        let mut prefilled = BTreeMap::new();
        prefilled.insert(SECRET_PATH.to_string(), SecretValue::from(String::new()));
        let err = apply_with_lookups(
            &store,
            &flags,
            ApplyOptions {
                mode: ApplyMode::Apply,
                non_interactive: true,
                prefilled_secrets: prefilled,
                ..ApplyOptions::default()
            },
            &|_| None,
            None,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("1 missing input(s)"), "{msg}");
        assert!(msg.contains("paste"), "names the paste source: {msg}");
        // Aborted before any mutation — no audit log written.
        assert!(!dir.path().join("local/audit/events.jsonl").exists());
    }

    #[test]
    fn emit_answers_template_writes_valid_manifest_and_touches_nothing() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let out = dir.path().join("template.env.json");
        let outcome = emit_answers_template(&out).expect("template emit succeeds");
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
            bundle_source_uri: None,
            remote_pins: None,
            idempotency_key: None,
            config_overrides: None,
            route_binding: Some(super::super::bundles::RouteBindingPayload {
                hosts: Vec::new(),
                path_prefixes: vec!["/v1".to_string()],
                tenant_selector: None,
            }),
            revenue_share: None,
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

    // --- G5: env-pack bindings ---

    #[test]
    fn pack_binding_add_then_idempotent() {
        let (dir, store) = seeded_store();
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "packs": [{
                "slot": "deployer",
                "kind": "greentic.deployer.local@1.0.0",
                "pack_ref": "builtin:deployer-local"
            }]
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        let outcome = run_apply(&store, &manifest_path).expect("add pack binding");
        let actions = step_actions(&outcome.result);
        assert!(
            actions.contains(&("add-pack-binding".to_string(), "create".to_string())),
            "must plan add-pack-binding: {actions:?}"
        );

        let env = load_local(&store);
        let binding = env.pack_for_slot(CapabilitySlot::Deployer);
        assert!(binding.is_some(), "deployer slot must be bound");
        let b = binding.unwrap();
        assert_eq!(b.kind.to_string(), "greentic.deployer.local@1.0.0");
        assert_eq!(b.pack_ref.as_str(), "builtin:deployer-local");

        // Idempotent re-apply.
        let second = run_apply(&store, &manifest_path).expect("re-apply");
        assert_eq!(second.result["changed"], 0, "{}", second.result);
    }

    #[test]
    fn pack_binding_update_on_kind_change() {
        let (dir, store) = seeded_store();
        // Seed with v1.
        let v1 = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "packs": [{
                "slot": "deployer",
                "kind": "greentic.deployer.local@1.0.0",
                "pack_ref": "builtin:deployer-local"
            }]
        });
        let v1_path = write_manifest(dir.path(), &v1);
        run_apply(&store, &v1_path).expect("first apply");

        // Update to v2.
        let v2 = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "packs": [{
                "slot": "deployer",
                "kind": "greentic.deployer.local@2.0.0",
                "pack_ref": "builtin:deployer-local-v2"
            }]
        });
        let v2_path = write_manifest(dir.path(), &v2);
        let plan = run_dry(&store, &v2_path).expect("dry-run");
        let actions = step_actions(&plan.result);
        assert!(
            actions.contains(&("update-pack-binding".to_string(), "update".to_string())),
            "must plan update-pack-binding: {actions:?}"
        );

        run_apply(&store, &v2_path).expect("apply update");
        let env = load_local(&store);
        let b = env.pack_for_slot(CapabilitySlot::Deployer).expect("bound");
        assert_eq!(b.kind.to_string(), "greentic.deployer.local@2.0.0");
        assert_eq!(b.pack_ref.as_str(), "builtin:deployer-local-v2");
        assert!(b.generation > 0, "generation must bump on update");
    }

    #[test]
    fn apply_stages_pack_answers_into_env_store() {
        let (dir, store) = seeded_store();
        // The answers file lives next to the manifest (manifest-relative ref).
        let answers = json!({"runtime_image": "ghcr.io/x/y:dev", "tunnel": "cloudflared"});
        std::fs::write(
            dir.path().join("deployer-answers.json"),
            serde_json::to_vec_pretty(&answers).unwrap(),
        )
        .unwrap();
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "packs": [{
                "slot": "deployer",
                "kind": "greentic.deployer.local@1.0.0",
                "pack_ref": "builtin:deployer-local",
                "answers_ref": "deployer-answers.json"
            }]
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        run_apply(&store, &manifest_path).expect("apply with answers_ref");

        // The file is staged into the env store at the canonical path...
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        let staged = env_dir.join("env-packs/deployer/answers.json");
        assert!(staged.is_file(), "answers must be staged at {staged:?}");
        let staged_val: Value = serde_json::from_slice(&std::fs::read(&staged).unwrap()).unwrap();
        assert_eq!(staged_val, answers);

        // ...and the binding records the env-relative staged ref, so reconcile
        // (which resolves against the env dir) finds it.
        let env = load_local(&store);
        let b = env.pack_for_slot(CapabilitySlot::Deployer).expect("bound");
        assert_eq!(
            b.answers_ref.as_deref(),
            Some(Path::new("env-packs/deployer/answers.json"))
        );

        // Idempotent: re-apply is a no-op (content unchanged).
        let second = run_apply(&store, &manifest_path).expect("re-apply");
        assert_eq!(second.result["changed"], 0, "{}", second.result);
    }

    #[test]
    fn apply_restages_pack_answers_on_content_change() {
        let (dir, store) = seeded_store();
        let p = dir.path().join("deployer-answers.json");
        std::fs::write(&p, br#"{"runtime_image":"img:v1"}"#).unwrap();
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "packs": [{
                "slot": "deployer",
                "kind": "greentic.deployer.local@1.0.0",
                "pack_ref": "builtin:deployer-local",
                "answers_ref": "deployer-answers.json"
            }]
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        run_apply(&store, &manifest_path).expect("first apply");

        // Edit the source content (same filename) and re-apply — the staged
        // copy must refresh even though the manifest ref string is unchanged.
        std::fs::write(&p, br#"{"runtime_image":"img:v2"}"#).unwrap();
        let plan = run_dry(&store, &manifest_path).expect("dry-run after edit");
        let actions = step_actions(&plan.result);
        assert!(
            actions.contains(&("update-pack-binding".to_string(), "update".to_string())),
            "content change must plan update-pack-binding: {actions:?}"
        );
        run_apply(&store, &manifest_path).expect("re-apply");
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        let staged = std::fs::read(env_dir.join("env-packs/deployer/answers.json")).unwrap();
        assert_eq!(staged, br#"{"runtime_image":"img:v2"}"#);
    }

    #[test]
    fn apply_with_oci_bundle_and_linking_endpoint() {
        let (dir, store) = seeded_store();
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{
                "bundle_id": "webchat-bot",
                "bundle_path": fixture(),
                "bundle_source_uri": "oci://ghcr.io/greenticai/demo/webchat-bot:v1",
                "route_binding": {
                    "path_prefixes": ["/"],
                    "tenant_selector": {"tenant": "tenant-default", "team": "default"}
                }
            }],
            "messaging_endpoints": [{
                "name": "webchat-bot",
                "provider_type": "messaging.telegram.bot",
                "links": ["webchat-bot"]
            }]
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        // The endpoint link resolves because the bundle is declared in the
        // manifest, and the OCI source is recorded on the staged revision so a
        // K8s worker can pull it at boot — both in a single apply.
        run_apply(&store, &manifest_path).expect("apply oci bundle + linking endpoint");
        let env = load_local(&store);
        assert_eq!(
            env.revisions[0].bundle_source_uri.as_deref(),
            Some("oci://ghcr.io/greenticai/demo/webchat-bot:v1"),
            "manifest bundle_source_uri must reach the staged revision"
        );
    }

    #[test]
    fn apply_multi_revision_threads_bundle_source_uri() {
        let (dir, store) = seeded_store();
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{
                "bundle_id": "split-bot",
                "revisions": [
                    {"name": "a", "bundle_path": fixture(), "weight_bps": 10000,
                     "bundle_source_uri": "oci://ghcr.io/greenticai/demo/split:a"}
                ]
            }]
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        run_apply(&store, &manifest_path).expect("apply split with oci source");
        let env = load_local(&store);
        assert_eq!(
            env.revisions[0].bundle_source_uri.as_deref(),
            Some("oci://ghcr.io/greenticai/demo/split:a"),
            "per-revision bundle_source_uri must reach the staged revision"
        );
    }

    #[test]
    fn adding_bundle_source_uri_to_converged_deployment_redeploys_and_sets_it() {
        let (dir, store) = seeded_store();
        // Deploy the bundle with NO OCI source — local-serve only.
        let m1 = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{"bundle_id": "b", "bundle_path": fixture()}]
        });
        let p1 = write_manifest(dir.path(), &m1);
        run_apply(&store, &p1).expect("first apply");
        assert!(
            load_local(&store)
                .revisions
                .iter()
                .all(|r| r.bundle_source_uri.is_none()),
            "baseline revision must have no pull ref"
        );

        // Re-apply the SAME artifact (same digest) but now declaring an OCI
        // source. Digest-only convergence would treat this as a no-op; the fix
        // must re-deploy so the live revision records the pull ref a K8s worker
        // needs to boot.
        let m2 = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "bundles": [{"bundle_id": "b", "bundle_path": fixture(),
                         "bundle_source_uri": "oci://ex/b:v1"}]
        });
        let p2 = write_manifest(dir.path(), &m2);
        run_apply(&store, &p2).expect("re-apply with oci source");
        let env = load_local(&store);
        assert!(
            env.revisions
                .iter()
                .any(|r| r.bundle_source_uri.as_deref() == Some("oci://ex/b:v1")),
            "adding bundle_source_uri to a same-digest deployment must (re)deploy a \
             revision carrying it; saw: {:?}",
            env.revisions
                .iter()
                .map(|r| r.bundle_source_uri.clone())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn answers_ref_drift_on_binding_is_repaired_even_when_staged_file_matches() {
        let (dir, store) = seeded_store();
        std::fs::write(dir.path().join("deployer-answers.json"), br#"{"x":1}"#).unwrap();
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "packs": [{
                "slot": "deployer",
                "kind": "greentic.deployer.local@1.0.0",
                "pack_ref": "builtin:deployer-local",
                "answers_ref": "deployer-answers.json"
            }]
        });
        let mp = write_manifest(dir.path(), &manifest);
        run_apply(&store, &mp).expect("first apply stages file + canonical ref");

        // Simulate an interrupted prior apply: the file is staged (content still
        // matches the manifest) but the binding never persisted its
        // `answers_ref`. Content-only drift detection would miss this.
        let mut env = load_local(&store);
        for b in &mut env.packs {
            if b.slot == CapabilitySlot::Deployer {
                b.answers_ref = None;
            }
        }
        store.save(&env).expect("save drifted env");

        // Re-apply: the ref mismatch must replan an update that restores the
        // canonical staged ref, even though the staged file content is unchanged.
        let plan = run_dry(&store, &mp).expect("dry-run on drifted binding");
        let actions = step_actions(&plan.result);
        assert!(
            actions.contains(&("update-pack-binding".to_string(), "update".to_string())),
            "a wrong/missing answers_ref must replan update-pack-binding: {actions:?}"
        );
        run_apply(&store, &mp).expect("re-apply repairs the ref");
        let env = load_local(&store);
        let b = env.pack_for_slot(CapabilitySlot::Deployer).expect("bound");
        assert_eq!(
            b.answers_ref.as_deref(),
            Some(Path::new("env-packs/deployer/answers.json")),
            "re-apply must restore the canonical staged answers_ref"
        );
    }

    #[test]
    fn pack_binding_rejects_messaging_slot() {
        let dir = tempdir().unwrap();
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "packs": [{
                "slot": "messaging",
                "kind": "greentic.messaging.telegram@1.0.0",
                "pack_ref": "builtin:msg"
            }]
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        let loaded: EnvManifest =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        let err = loaded.validate_shape().unwrap_err();
        assert!(err.to_string().contains("messaging"), "got: {err}");
    }

    // --- G6: extensions ---

    #[test]
    fn extension_add_then_idempotent() {
        let (dir, store) = seeded_store();
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "extensions": [{
                "kind": "greentic.ext.memory@1.0.0",
                "pack_ref": "builtin:memory-chronicle",
                "instance_id": "default"
            }]
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        let outcome = run_apply(&store, &manifest_path).expect("add extension");
        let actions = step_actions(&outcome.result);
        assert!(
            actions.contains(&("add-extension".to_string(), "create".to_string())),
            "must plan add-extension: {actions:?}"
        );

        let env = load_local(&store);
        assert_eq!(env.extensions.len(), 1);
        let ext = &env.extensions[0];
        assert_eq!(ext.kind.to_string(), "greentic.ext.memory@1.0.0");
        assert_eq!(ext.pack_ref.as_str(), "builtin:memory-chronicle");
        assert_eq!(ext.instance_id.as_deref(), Some("default"));

        // Idempotent re-apply.
        let second = run_apply(&store, &manifest_path).expect("re-apply");
        assert_eq!(second.result["changed"], 0, "{}", second.result);
    }

    #[test]
    fn extension_update_on_pack_ref_change() {
        let (dir, store) = seeded_store();
        let v1 = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "extensions": [{
                "kind": "greentic.ext.memory@1.0.0",
                "pack_ref": "builtin:memory-v1"
            }]
        });
        let v1_path = write_manifest(dir.path(), &v1);
        run_apply(&store, &v1_path).expect("first apply");

        let v2 = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "extensions": [{
                "kind": "greentic.ext.memory@1.0.0",
                "pack_ref": "builtin:memory-v2"
            }]
        });
        let v2_path = write_manifest(dir.path(), &v2);
        let plan = run_dry(&store, &v2_path).expect("dry-run");
        let actions = step_actions(&plan.result);
        assert!(
            actions.contains(&("update-extension".to_string(), "update".to_string())),
            "must plan update-extension: {actions:?}"
        );

        run_apply(&store, &v2_path).expect("apply update");
        let env = load_local(&store);
        assert_eq!(env.extensions[0].pack_ref.as_str(), "builtin:memory-v2");
        assert!(
            env.extensions[0].generation > 0,
            "generation must bump on update"
        );
    }

    #[test]
    fn extension_bad_instance_id_rejected_by_shape() {
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "extensions": [{
                "kind": "greentic.ext.memory@1.0.0",
                "pack_ref": "builtin:memory",
                "instance_id": "BAD_ID!"
            }]
        });
        let loaded: EnvManifest = serde_json::from_value(manifest).unwrap();
        let err = loaded.validate_shape().unwrap_err();
        assert!(err.to_string().contains("instance_id"), "got: {err}");
    }

    #[test]
    fn extension_duplicate_key_rejected_by_shape() {
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "extensions": [
                {"kind": "greentic.ext.memory@1.0.0", "pack_ref": "a", "instance_id": "x"},
                {"kind": "greentic.ext.memory@2.0.0", "pack_ref": "b", "instance_id": "x"},
            ]
        });
        let loaded: EnvManifest = serde_json::from_value(manifest).unwrap();
        let err = loaded.validate_shape().unwrap_err();
        assert!(err.to_string().contains("duplicate"), "got: {err}");
    }

    // --- G7: host-config reconcile ---

    #[test]
    fn host_config_reconcile_then_idempotent() {
        let (dir, store) = seeded_store();
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {
                "id": "local",
                "name": "Local Dev",
                "region": "eu-west-1",
                "tenant_org_id": "org-99",
                "listen_addr": "0.0.0.0:9090"
            }
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        let outcome = run_apply(&store, &manifest_path).expect("host-config apply");
        let actions = step_actions(&outcome.result);
        assert!(
            actions.contains(&("update-host-config".to_string(), "update".to_string()))
                || actions.contains(&("update-host-config".to_string(), "create".to_string())),
            "must plan update-host-config: {actions:?}"
        );

        let env = load_local(&store);
        assert_eq!(env.name, "Local Dev");
        assert_eq!(env.host_config.region.as_deref(), Some("eu-west-1"));
        assert_eq!(env.host_config.tenant_org_id.as_deref(), Some("org-99"));
        assert_eq!(
            env.host_config.listen_addr,
            Some("0.0.0.0:9090".parse().unwrap())
        );

        // Idempotent re-apply.
        let second = run_apply(&store, &manifest_path).expect("re-apply");
        assert_eq!(second.result["changed"], 0, "{}", second.result);
    }

    #[test]
    fn gui_enabled_reconcile_then_idempotent() {
        let (dir, store) = seeded_store();
        // `local` resolves GUI-on by default; declaring `false` is an explicit
        // override that must persist and survive a re-apply as a no-op.
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {
                "id": "local",
                "gui_enabled": false
            }
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        let outcome = run_apply(&store, &manifest_path).expect("gui apply");
        let actions = step_actions(&outcome.result);
        assert!(
            actions.contains(&("update-host-config".to_string(), "update".to_string())),
            "must plan update-host-config for gui_enabled: {actions:?}"
        );

        let env = load_local(&store);
        assert_eq!(env.host_config.gui_enabled, Some(false));
        assert!(
            !env.host_config.resolved_gui_enabled(),
            "explicit false overrides the local default-on"
        );

        // Idempotent re-apply.
        let second = run_apply(&store, &manifest_path).expect("re-apply");
        assert_eq!(second.result["changed"], 0, "{}", second.result);
    }

    #[test]
    fn host_config_bad_listen_addr_rejected_by_shape() {
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {
                "id": "local",
                "listen_addr": "not-an-addr"
            }
        });
        let loaded: EnvManifest = serde_json::from_value(manifest).unwrap();
        let err = loaded.validate_shape().unwrap_err();
        assert!(err.to_string().contains("listen_addr"), "got: {err}");
    }

    // --- G5+G6 ordering ---

    #[test]
    fn packs_before_secrets_extensions_before_endpoints() {
        let (dir, store) = seeded_store_with_dev_secrets();
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "packs": [{
                "slot": "deployer",
                "kind": "greentic.deployer.local@1.0.0",
                "pack_ref": "builtin:deployer-local"
            }],
            "secrets": [{"path": SECRET_PATH, "from_env": "APPLY_ORDER_VAR"}],
            "bundles": [{"bundle_id": "quickstart", "bundle_path": fixture()}],
            "extensions": [{
                "kind": "greentic.ext.memory@1.0.0",
                "pack_ref": "builtin:memory"
            }],
            "messaging_endpoints": [{
                "name": "bot",
                "provider_type": "messaging.telegram.bot",
                "links": ["quickstart"]
            }]
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        let lookup = |_: &str| Some("tok".to_string());
        let plan =
            run_with_lookup(&store, &manifest_path, ApplyMode::DryRun, &lookup).expect("dry-run");
        let steps = plan.result["steps"].as_array().expect("steps");
        let pos = |kind: &str| {
            steps
                .iter()
                .position(|s| s["kind"] == kind)
                .unwrap_or_else(|| panic!("no `{kind}` step in {steps:?}"))
        };
        assert!(pos("ensure-environment") < pos("add-pack-binding"));
        assert!(pos("add-pack-binding") < pos("put-secret"));
        assert!(pos("put-secret") < pos("deploy-bundle"));
        assert!(pos("deploy-bundle") < pos("add-extension"));
        assert!(pos("add-extension") < pos("add-endpoint"));
    }

    // --- G5 fresh-env pack diff against default bindings ---

    /// On a fresh local env (no env on disk), `env init` will create 5 default
    /// pack bindings. The planner must diff manifest packs against those
    /// defaults so a pack targeting a default slot emits UpdatePackBinding (if
    /// the desired binding differs) or a no-op (if identical), never an
    /// unconditional AddPackBinding that would fail with SlotAlreadyBound.
    /// A pack targeting a non-default slot (e.g. revocation) still correctly
    /// emits AddPackBinding.
    #[test]
    fn fresh_env_pack_on_default_slot_emits_update_not_add() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        // No env on disk — this is a fresh-env scenario.

        // Pack 1: deployer with SAME kind+pack_ref as the default → no-op.
        // Pack 2: telemetry with DIFFERENT kind → update.
        // Pack 3: revocation (not in defaults) → add.
        let manifest = json!({
            "schema": ENV_MANIFEST_SCHEMA_V1,
            "environment": {"id": "local"},
            "packs": [
                {
                    "slot": "deployer",
                    "kind": crate::defaults::LOCAL_DEPLOYER_PACK,
                    "pack_ref": crate::defaults::LOCAL_DEPLOYER_PACK
                },
                {
                    "slot": "telemetry",
                    "kind": "greentic.telemetry.otlp@2.0.0",
                    "pack_ref": "builtin:otlp"
                },
                {
                    "slot": "revocation",
                    "kind": "greentic.revocation.crl@1.0.0",
                    "pack_ref": "builtin:crl"
                }
            ]
        });
        let manifest_path = write_manifest(dir.path(), &manifest);
        let plan = run_dry(&store, &manifest_path).expect("dry-run on fresh env");
        let steps = plan.result["steps"].as_array().expect("steps array");

        // Find each pack step by its key (= slot name).
        let find_step = |key: &str| {
            steps
                .iter()
                .find(|s| s["key"] == key)
                .unwrap_or_else(|| panic!("no step with key `{key}` in {steps:?}"))
        };

        // deployer: identical to default → no-op (kind is still add-pack-binding
        // because the no-op variant reuses that kind label).
        let deployer = find_step("deployer");
        assert_eq!(
            deployer["action"].as_str().unwrap(),
            "no-op",
            "deployer must be no-op (matches default): {deployer}"
        );

        // telemetry: differs from default → update-pack-binding.
        let telemetry = find_step("telemetry");
        assert_eq!(
            telemetry["kind"].as_str().unwrap(),
            "update-pack-binding",
            "telemetry must be update (differs from default): {telemetry}"
        );
        assert_eq!(
            telemetry["action"].as_str().unwrap(),
            "update",
            "telemetry action must be update: {telemetry}"
        );

        // revocation: not in defaults → add-pack-binding.
        let revocation = find_step("revocation");
        assert_eq!(
            revocation["kind"].as_str().unwrap(),
            "add-pack-binding",
            "revocation must be add (not in defaults): {revocation}"
        );
        assert_eq!(
            revocation["action"].as_str().unwrap(),
            "create",
            "revocation action must be create: {revocation}"
        );
    }
}
