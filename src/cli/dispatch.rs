//! Clap-derive dispatcher for `greentic-deployer op …` (`A3`).
//!
//! Owns the `OpCommand` clap tree + the `dispatch_op` entry point. The
//! actual per-noun command logic lives in `cli::env`/`cli::env_packs`/etc;
//! this module is the wiring layer that converts argv → typed payloads →
//! library calls and prints the JSON envelope to stdout.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use greentic_deploy_spec::CapabilitySlot;

use crate::environment::LocalFsStore;

use super::{OpError, OpFlags, OpOutcome, render_error};

/// `greentic-deployer op …`. Mirrors the `gtc op …` surface; the gtc-side
/// passthrough shells out to `greentic-operator op …`, which dispatches
/// through the same `OpCommand` clap tree.
#[derive(Parser, Debug)]
#[command(
    after_help = "Nouns: env, env-packs, extensions, bundles, revisions, traffic, config, credentials, secrets, messaging.\n\
                  Every verb honors:\n\
                    --schema             dump the JSON schema of the payload it would accept, then exit\n\
                    --answers <PATH>     read the payload from a JSON or YAML file\n\n\
                  Examples:\n\
                    greentic-operator op env create --answers env.json\n\
                    greentic-operator op revisions warm --answers warm.yaml\n\
                    greentic-operator op env show <env-id>\n\n\
                  Errors are written to stderr as a JSON envelope:\n\
                    {\"op\":\"<verb>\",\"noun\":\"<noun>\",\"error\":{\"kind\":\"…\",\"message\":\"…\"}}\n\
                  Success output goes to stdout as:\n\
                    {\"op\":\"<verb>\",\"noun\":\"<noun>\",\"result\":…}"
)]
pub struct OpCommand {
    /// Optional root for the local `EnvironmentStore`. Defaults to
    /// `~/.greentic/environments`.
    #[arg(long, global = true)]
    pub store_root: Option<PathBuf>,

    /// Target a remote operator store over HTTP instead of the local FS
    /// store. Overrides `GREENTIC_STORE_URL`. When set (and not `--schema`),
    /// mutation verbs run against the remote A8 HTTP store.
    #[arg(long, global = true)]
    pub store_url: Option<String>,

    /// Bearer token for the remote `--store-url` store. Overrides
    /// `GREENTIC_STORE_TOKEN`.
    #[arg(long, global = true)]
    pub store_token: Option<String>,

    /// Dump the JSON Schema of the input payload this verb accepts, then
    /// exit. The library is free to return a hand-written stub until A1's
    /// `schemars` derive wiring lands.
    #[arg(long, global = true)]
    pub schema: bool,

    /// Read the verb's payload from this JSON or YAML file instead of
    /// reading positionals.
    #[arg(long, global = true)]
    pub answers: Option<PathBuf>,

    #[command(subcommand)]
    pub noun: OpNoun,
}

#[derive(Subcommand, Debug)]
pub enum OpNoun {
    /// Environment CRUD (`create`/`update`/`list`/`show`/`doctor`/`destroy`).
    Env {
        #[command(subcommand)]
        verb: EnvVerb,
    },
    /// Env-pack bindings (`add`/`update`/`remove`/`rollback`/`list`).
    EnvPacks {
        #[command(subcommand)]
        verb: EnvPacksVerb,
    },
    /// Application bundle deployments.
    Bundles {
        #[command(subcommand)]
        verb: BundlesVerb,
    },
    /// Revision lifecycle.
    Revisions {
        #[command(subcommand)]
        verb: RevisionsVerb,
    },
    /// Traffic split per deployment.
    Traffic {
        #[command(subcommand)]
        verb: TrafficVerb,
    },
    /// One-shot bundle deployment: add (if new) → stage → warm → route 100 %
    /// traffic, with sensible defaults. Re-deploying an existing bundle stages
    /// a new revision and blue-green shifts traffic onto it. The
    /// `bundles`/`revisions`/`traffic` verbs remain for fine-tuning.
    Deploy(BundleDeployArgs),
    /// Host/setup/runtime config inspection.
    Config {
        #[command(subcommand)]
        verb: ConfigVerb,
    },
    /// Cloud credentials.
    Credentials {
        #[command(subcommand)]
        verb: CredentialsVerb,
    },
    /// Secrets management.
    Secrets {
        #[command(subcommand)]
        verb: SecretsVerb,
    },
    /// Per-environment trust-root management (C2). Lists, adds, or removes
    /// `(key_id, public_pem)` pairs verifiers consult to validate DSSE
    /// envelopes (revenue policy today; bundle/revision signatures next).
    #[command(name = "trust-root")]
    TrustRoot {
        #[command(subcommand)]
        verb: TrustRootVerb,
    },
    /// Per-environment messaging endpoints (`Phase M1`). N-per-env instances
    /// of messaging providers (e.g. multiple Teams bots), each with its own
    /// curated bundle set and optional welcome flow.
    Messaging {
        #[command(subcommand)]
        verb: MessagingNoun,
    },
    /// Open-namespace extension bindings (`Path 3`). N-per-env capabilities
    /// resolved by workloads via `ext://<path>[/<instance>]` — config-shaped,
    /// no typed host interface, no schema bump per family. Contrast
    /// `env-packs`, which manages the closed, 1-per-slot core `packs`.
    Extensions {
        #[command(subcommand)]
        verb: ExtensionsVerb,
    },
}

#[derive(Subcommand, Debug)]
pub enum MessagingNoun {
    /// Manage a per-environment messaging endpoint (`add`/`list`/`show`/
    /// `link-bundle`/`unlink-bundle`/`set-welcome-flow`/`remove`).
    Endpoint {
        #[command(subcommand)]
        verb: MessagingEndpointVerb,
    },
}

#[derive(Subcommand, Debug)]
pub enum MessagingEndpointVerb {
    /// Mint a new endpoint for `<env>` with `<provider_type>` /
    /// `<provider_id>` instance identity. Bundle linkage and welcome-flow
    /// follow via dedicated verbs.
    Add(MessagingEndpointAddArgs),
    /// List every endpoint in `<env>`.
    List { env_id: String },
    /// Show one endpoint in `<env>` by `<endpoint_id>` (ULID).
    Show { env_id: String, endpoint_id: String },
    /// Link a bundle to an endpoint. Bundle must already be deployed in the env.
    #[command(name = "link-bundle")]
    LinkBundle(MessagingEndpointLinkBundleArgs),
    /// Remove a bundle from an endpoint's `linked_bundles`. Fails when the
    /// bundle owns the endpoint's welcome_flow — clear that first.
    #[command(name = "unlink-bundle")]
    UnlinkBundle(MessagingEndpointLinkBundleArgs),
    /// Set the endpoint's default welcome flow (referenced on first contact
    /// per M1.5). The flow's bundle must already be linked.
    #[command(name = "set-welcome-flow")]
    SetWelcomeFlow(MessagingEndpointSetWelcomeFlowArgs),
    /// Remove an endpoint. Idempotent: removing an absent endpoint succeeds.
    Remove(MessagingEndpointRemoveArgs),
    /// Rotate the webhook secret on an existing endpoint. Generates a fresh
    /// 32-char CSPRNG secret, bumps generation. Idempotent on the same key.
    #[command(name = "rotate-webhook-secret")]
    RotateWebhookSecret(MessagingEndpointRemoveArgs),
}

/// Inline-flag form of `messaging.endpoint add`. When all required fields
/// (`--env`, `--provider-type`, `--provider-id`, `--display-name`,
/// `--idempotency-key`, `--updated-by`) are present, the payload is built
/// directly from these flags. Otherwise dispatch falls through to
/// `--answers <PATH>` / `--schema`, matching the `trust-root add` precedent.
#[derive(Args, Debug)]
pub struct MessagingEndpointAddArgs {
    /// Environment id, e.g. `local`.
    #[arg(long)]
    pub env: Option<String>,
    /// Provider type — `telegram`, `teams`, `slack`, `whatsapp`, `webex`,
    /// `email`, `webchat`.
    #[arg(long = "provider-type")]
    pub provider_type: Option<String>,
    /// Per-environment instance identity for the provider, e.g.
    /// `telegram-legal-bot`. Together with `--provider-type` it must be
    /// unique inside the env.
    #[arg(long = "provider-id")]
    pub provider_id: Option<String>,
    /// Human-readable label for the endpoint.
    #[arg(long = "display-name")]
    pub display_name: Option<String>,
    /// Secret reference URI, e.g. `secret://local/global/telegram/bot_token`.
    /// Repeating.
    #[arg(long = "secret-ref", value_name = "URI")]
    pub secret_ref: Vec<String>,
    /// Idempotency key. Required for safe retries; mutations replay no-op when
    /// the same key + identity is supplied.
    #[arg(long = "idempotency-key")]
    pub idempotency_key: Option<String>,
    /// Free-form actor label that appears in the env-audit log.
    #[arg(long = "updated-by")]
    pub updated_by: Option<String>,
}

/// Inline-flag form of `messaging.endpoint link-bundle` and `unlink-bundle`.
/// When all four required fields are present the payload is built directly;
/// otherwise dispatch falls through to `--answers` / `--schema`.
#[derive(Args, Debug)]
pub struct MessagingEndpointLinkBundleArgs {
    /// Environment id.
    #[arg(long)]
    pub env: Option<String>,
    /// Endpoint id (ULID).
    #[arg(long = "endpoint-id")]
    pub endpoint_id: Option<String>,
    /// Bundle id. Must already be deployed in the env.
    #[arg(long = "bundle-id")]
    pub bundle_id: Option<String>,
    /// Idempotency key.
    #[arg(long = "idempotency-key")]
    pub idempotency_key: Option<String>,
    /// Free-form actor label.
    #[arg(long = "updated-by")]
    pub updated_by: Option<String>,
}

/// Inline-flag form of `messaging.endpoint set-welcome-flow`. When all six
/// required fields are present the payload is built directly; otherwise
/// dispatch falls through to `--answers` / `--schema`.
#[derive(Args, Debug)]
pub struct MessagingEndpointSetWelcomeFlowArgs {
    /// Environment id.
    #[arg(long)]
    pub env: Option<String>,
    /// Endpoint id (ULID).
    #[arg(long = "endpoint-id")]
    pub endpoint_id: Option<String>,
    /// Bundle id of the welcome-flow's pack. Must already be linked to the
    /// endpoint via `link-bundle`.
    #[arg(long = "bundle-id")]
    pub bundle_id: Option<String>,
    /// Pack id that hosts the welcome flow.
    #[arg(long = "pack-id")]
    pub pack_id: Option<String>,
    /// Flow id (the welcome-flow entry point).
    #[arg(long = "flow-id")]
    pub flow_id: Option<String>,
    /// Idempotency key.
    #[arg(long = "idempotency-key")]
    pub idempotency_key: Option<String>,
    /// Free-form actor label.
    #[arg(long = "updated-by")]
    pub updated_by: Option<String>,
}

/// Inline-flag form of `messaging.endpoint remove` and `rotate-webhook-secret`.
/// When all four required fields are present the payload is built directly;
/// otherwise dispatch falls through to `--answers` / `--schema`.
#[derive(Args, Debug)]
pub struct MessagingEndpointRemoveArgs {
    /// Environment id.
    #[arg(long)]
    pub env: Option<String>,
    /// Endpoint id (ULID).
    #[arg(long = "endpoint-id")]
    pub endpoint_id: Option<String>,
    /// Idempotency key.
    #[arg(long = "idempotency-key")]
    pub idempotency_key: Option<String>,
    /// Free-form actor label.
    #[arg(long = "updated-by")]
    pub updated_by: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum EnvVerb {
    /// Idempotent bootstrap of the `local` environment with the five default
    /// env-pack bindings (A4 helper exposed as a CLI verb). Creates the env
    /// if missing, fills in any missing default bindings on an existing env,
    /// or reports `untouched` if the env is already complete. User-bound
    /// non-default descriptors are NEVER overwritten.
    Init(EnvInitArgs),
    /// Declarative, upsert-only environment apply. Reads a
    /// `greentic.env-manifest.v1` document via `--answers <PATH>` and
    /// reconciles the env toward it: validate → diff → plan → execute →
    /// verify. Re-running an unchanged manifest is a visible no-op.
    /// `--dry-run` previews the plan; `--check` is the CI gate (exit 1 on
    /// pending diff).
    Apply(EnvApplyArgs),
    Create(EnvCreateArgs),
    Update(EnvUpdateArgs),
    /// `op env set-public-url <env_id> <URL>`. Replaces the env's persisted
    /// `host_config.public_base_url`. Equivalent to
    /// `op config set --public-url <URL>` but easier to discover for the
    /// common "I set the URL once and forget it" path.
    SetPublicUrl(EnvSetPublicUrlArgs),
    List,
    Show {
        env_id: String,
    },
    Doctor {
        env_id: String,
    },
    /// Run per-binding tool preflight. Resolves each env-pack binding via the
    /// registry and invokes its handler's `preflight()` to check external
    /// tools (binary presence, version, auth, scope) needed for real work.
    /// The built-in `local` handlers report no external tools.
    ToolCheck {
        env_id: String,
    },
    Destroy {
        env_id: String,
        #[arg(long)]
        confirm: bool,
    },
    /// Migrate the legacy `dev` environment to `<target>` (typically `local`).
    /// Run with `--check` to scan without touching state; `--apply` performs
    /// the one-shot rewrite only when the check is clean (A4b).
    MigrateDev {
        /// Target env id — typically `local`.
        target: String,
        /// Scan for blocking findings and report; do not touch state.
        #[arg(long, conflicts_with = "apply")]
        check: bool,
        /// Re-run the check; if clean, perform the migration.
        #[arg(long, conflicts_with = "check")]
        apply: bool,
    },
    /// Archive the legacy `<state_dir>/deploy/` artifact tree (A6).
    /// `--apply` renames it to a hidden `.deploy-migrated-<ts>/` sentinel;
    /// contents are NOT copied into the new layout. Quiesce live deploys
    /// first — `apply::run` does not participate in the migration lock.
    MigrateState {
        /// Target env id — must exist in EnvironmentStore.
        target: String,
        /// Scan for blocking findings and report; do not touch state.
        #[arg(long, conflicts_with = "apply")]
        check: bool,
        /// Re-run the check; if clean, rename the legacy tree.
        #[arg(long, conflicts_with = "check")]
        apply: bool,
        /// Override the legacy state-dir root. Defaults to
        /// `$HOME/.greentic/state`.
        #[arg(long = "state-dir")]
        state_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum TrustRootVerb {
    /// Seed the env trust root with the local operator key. The
    /// revenue-policy writer never auto-seeds, so this verb is the
    /// authorized path that grants signing rights to a new env. Idempotent.
    Bootstrap { env_id: Option<String> },
    /// List trusted keys for one env.
    List { env_id: String },
    /// Add a `(key_id, public_pem)` pair. PEM source: `--public-key-pem` (inline)
    /// or `--public-key-file <PATH>`.
    Add(TrustRootAddArgs),
    /// Remove a key by `key_id` (case-insensitive). No-op if absent.
    Remove(TrustRootRemoveArgs),
}

#[derive(Args, Debug)]
pub struct TrustRootAddArgs {
    pub env_id: Option<String>,
    #[arg(long = "key-id")]
    pub key_id: Option<String>,
    #[arg(long = "public-key-pem")]
    pub public_key_pem: Option<String>,
    #[arg(long = "public-key-file")]
    pub public_key_file: Option<PathBuf>,
}

/// Args for `op env init`. Only `--public-url` is settable inline;
/// init is otherwise an idempotent bootstrap of the canonical `local` env.
/// If the env already exists, an inline `--public-url` is NOT applied —
/// use `op env set-public-url` (or `op config set --public-url`) to mutate
/// an existing env's URL.
#[derive(Args, Debug)]
pub struct EnvInitArgs {
    /// Persistent public base URL the runtime exposes
    /// (`https://host[:port]`, origin only). Stored in
    /// `Environment.host_config.public_base_url`. Only takes effect when
    /// `init` actually creates the env; on `untouched` / `healed` outcomes
    /// the existing URL is preserved.
    #[arg(long = "public-url")]
    pub public_url: Option<String>,
}

/// Args for `op env apply`. The manifest itself arrives via the global
/// `--answers <PATH>` flag (it IS the verb's payload); these flags only
/// shape how the plan is executed.
#[derive(Args, Debug)]
pub struct EnvApplyArgs {
    /// Validate + diff + print the plan, then exit without mutating
    /// anything (exit 0 even when changes are pending — it's a preview).
    #[arg(long = "dry-run")]
    pub dry_run: bool,
    /// CI convergence gate: validate + diff + print the plan, then exit
    /// non-zero when the plan contains pending diffable changes, 0 when the
    /// env is converged. Always-put secret steps don't count as drift
    /// (values cannot be diffed until A9); they're reported separately.
    /// Never mutates anything.
    #[arg(long, conflicts_with = "dry_run")]
    pub check: bool,
    /// Audit principal forwarded to every composed mutation. Defaults to
    /// `env-apply`.
    #[arg(long = "updated-by")]
    pub updated_by: Option<String>,
    /// Skip the interactive confirmation shown when the plan contains
    /// mutations and stdin/stdout are a TTY. Non-TTY implies `--yes`.
    #[arg(long)]
    pub yes: bool,
}

impl EnvApplyArgs {
    /// clap's `conflicts_with` guarantees at most one of `--dry-run` /
    /// `--check` is set.
    fn mode(&self) -> super::env_apply::ApplyMode {
        use super::env_apply::ApplyMode;
        if self.check {
            ApplyMode::Check
        } else if self.dry_run {
            ApplyMode::DryRun
        } else {
            ApplyMode::Apply
        }
    }
}

/// Args for `op env create` and `op env update`. All fields are optional
/// at the clap layer so `--answers` / `--schema` keep working unchanged;
/// the dispatcher builds an `EnvCreatePayload` only when the required
/// inline flags are supplied, otherwise hands `None` to the library
/// function (`resolve_payload` then defers to `--answers`).
#[derive(Args, Debug)]
pub struct EnvCreateArgs {
    /// Environment id (e.g. `local`, `prod-eu`).
    pub environment_id: Option<String>,
    /// Display name. Defaults to `--environment-id` if omitted on the CLI
    /// path; required on the JSON path. Pass either positionally below or
    /// via `--name`.
    #[arg(long = "name")]
    pub name: Option<String>,
    /// Optional region tag (free-form).
    #[arg(long = "region")]
    pub region: Option<String>,
    /// Tenant organization id this env belongs to.
    #[arg(long = "tenant-org")]
    pub tenant_org_id: Option<String>,
    /// Bind address for the runtime's local HTTP listener (e.g.
    /// `127.0.0.1:8080`). Validated as `SocketAddr` before any state is
    /// touched.
    #[arg(long = "listen-addr")]
    pub listen_addr: Option<String>,
    /// Persistent public base URL the runtime exposes
    /// (`https://host[:port]`, origin only).
    #[arg(long = "public-url")]
    pub public_url: Option<String>,
}

/// Args for `op env update`. Update accepts the metadata fields only.
/// URL changes go through `op env set-public-url` (single-field verb)
/// or `op config set --public-url` (URL inside a multi-field host_config
/// update); listen-addr changes through `op config set --listen-addr`.
#[derive(Args, Debug)]
pub struct EnvUpdateArgs {
    /// Environment id (e.g. `local`, `prod-eu`).
    pub environment_id: Option<String>,
    /// Display name. Defaults to `--environment-id` if omitted on the CLI
    /// path; required on the JSON path. Pass either positionally below or
    /// via `--name`.
    #[arg(long = "name")]
    pub name: Option<String>,
    /// Optional region tag (free-form).
    #[arg(long = "region")]
    pub region: Option<String>,
    /// Tenant organization id this env belongs to.
    #[arg(long = "tenant-org")]
    pub tenant_org_id: Option<String>,
}

/// Args for `op env set-public-url <env_id> <URL>`. Both fields are
/// required positional — this verb only sets the public URL, no other
/// host_config fields. `--answers` is rejected: this is a dedicated
/// single-purpose verb, not an `op config set` alias.
#[derive(Args, Debug)]
pub struct EnvSetPublicUrlArgs {
    /// Environment id (e.g. `local`).
    pub env_id: String,
    /// Public base URL the runtime exposes (`https://host[:port]`, origin
    /// only — no path, query, or fragment).
    pub url: String,
}

#[derive(Args, Debug)]
pub struct TrustRootRemoveArgs {
    pub env_id: Option<String>,
    #[arg(long = "key-id")]
    pub key_id: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum EnvPacksVerb {
    Add,
    Update,
    Remove,
    Rollback,
    List { env_id: String },
}

#[derive(Subcommand, Debug)]
pub enum ExtensionsVerb {
    Add,
    Update,
    Remove,
    Rollback,
    List { env_id: String },
}

#[derive(Subcommand, Debug)]
pub enum BundlesVerb {
    Add,
    Update,
    Remove,
    List { env_id: String },
}

#[derive(Subcommand, Debug)]
pub enum RevisionsVerb {
    Stage(RevisionStageArgs),
    Warm,
    Drain,
    Archive,
    List { env_id: String },
}

/// Args for `op revisions stage`. All fields are optional at the clap layer so
/// `--answers` / `--payload-json` / `--schema` keep working unchanged; the
/// dispatcher builds a `RevisionStagePayload` only when the positional args are
/// supplied, otherwise hands `None` to the library function.
#[derive(Args, Debug)]
pub struct RevisionStageArgs {
    /// Environment id, e.g. `local`.
    pub env_id: Option<String>,
    /// Deployment ULID the revision belongs to.
    #[arg(long)]
    pub deployment: Option<String>,
    /// Local `.gtbundle` to extract and pin into the revision's pack-list.
    #[arg(long)]
    pub bundle: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum TrafficVerb {
    /// Replace the traffic split for one deployment. Entries are
    /// `<revision_id>=<percent>` (integer 0..=100, optional `%` suffix) or
    /// `<revision_id>=<N>bps` (basis points 0..=10_000). Sum must equal
    /// 100 % (10,000 bps). Validates revisions are `Ready` before saving.
    Set(TrafficSetArgs),
    /// Show the live split for one deployment.
    Show(TrafficTargetArgs),
    /// Roll back to the previously-saved split for one deployment.
    Rollback(TrafficTargetArgs),
}

/// Args for `op traffic set`. All fields are optional at the clap layer so
/// that `--answers` / `--payload-json` / `--schema` continue to work
/// unchanged; the dispatcher builds a `TrafficSetPayload` only when the
/// required clap args are supplied, and otherwise hands `None` to the
/// library function so it can resolve the payload from `--answers`.
#[derive(Args, Debug)]
pub struct TrafficSetArgs {
    /// Environment id, e.g. `local`.
    pub env_id: Option<String>,
    /// Repeated `<revision_id>=<weight>` entries — weight is `N`/`N%`
    /// (percent) or `Nbps` (basis points). Sum must reach 100 %.
    pub entries: Vec<String>,
    /// Deployment ULID.
    #[arg(long)]
    pub deployment: Option<String>,
    /// Idempotency key (required). Same key = no-op replay; different key
    /// overwrites the rollback target. Any stable string works.
    #[arg(long)]
    pub idempotency_key: Option<String>,
    /// Actor recorded on the split. Defaults to `operator`.
    #[arg(long)]
    pub updated_by: Option<String>,
    /// Sidecar authorization-doc path. Defaults to `auth.json`.
    #[arg(long)]
    pub authorization_ref: Option<PathBuf>,
}

/// Args for `op deploy`. All fields are optional at the clap layer so
/// `--answers` / `--schema` keep working unchanged; the dispatcher builds a
/// `BundleDeployPayload` only when args are supplied, and requires `--bundle`
/// on that direct path.
#[derive(Args, Debug)]
pub struct BundleDeployArgs {
    /// Local `.gtbundle` to deploy. Required on the direct CLI path.
    #[arg(long)]
    pub bundle: Option<PathBuf>,
    /// Environment id. Defaults to `local`.
    #[arg(long)]
    pub env: Option<String>,
    /// Bundle id. Defaults to the `.gtbundle` filename stem.
    #[arg(long = "bundle-id")]
    pub bundle_id: Option<String>,
    /// Billing principal (P6). Defaults to `local-dev` on the `local` env;
    /// required for any other env.
    #[arg(long = "customer-id")]
    pub customer_id: Option<String>,
    /// Idempotency key for the traffic cut-over. Defaults to a value derived
    /// from the freshly-minted revision id.
    #[arg(long = "idempotency-key")]
    pub idempotency_key: Option<String>,
    /// D.4: per-pack provider config override (string values). Repeating,
    /// formatted as `<pack_id>:<key>=<value>`. The value is ALWAYS stored as
    /// a JSON string — no type coercion. Use `--config-override-json` for
    /// typed values (bool, number, object, array).
    /// Example: `--config-override messaging-telegram:api_base_url=https://staging.example.com`.
    #[arg(long = "config-override", value_name = "PACK_ID:KEY=VALUE")]
    pub config_override: Vec<String>,
    /// D.4: per-pack provider config override (typed JSON values). Repeating,
    /// formatted as `<pack_id>:<key>=<json>`. The value is parsed as JSON;
    /// a parse error is rejected. Both `--config-override` and
    /// `--config-override-json` merge into the same map (later flags win
    /// per-(pack,key)).
    /// Example: `--config-override-json messaging-telegram:retry_max=5`.
    #[arg(long = "config-override-json", value_name = "PACK_ID:KEY=JSON")]
    pub config_override_json: Vec<String>,
    /// D.4: bulk-load config overrides from a JSON file shaped
    /// `{"<pack_id>": {"<key>": <value>, ...}, ...}`. Individual
    /// `--config-override` / `--config-override-json` flags MERGE on top
    /// (per-pack, per-key).
    #[arg(long = "config-overrides-from", value_name = "FILE")]
    pub config_overrides_from: Option<PathBuf>,
    /// Route binding: path prefix to dispatch into this bundle, e.g. `/legal`.
    /// Repeating. Sets `route_binding.path_prefixes` at deploy time so a
    /// follow-up `bundles update` isn't needed for the common case.
    #[arg(long = "path-prefix", value_name = "PREFIX")]
    pub path_prefix: Vec<String>,
    /// Route binding: host to dispatch into this bundle. Repeating.
    /// Sets `route_binding.hosts` at deploy time.
    #[arg(long = "host", value_name = "HOST")]
    pub host: Vec<String>,
    /// Route binding: tenant id for `tenant_selector`. When supplied, the
    /// resolved deployment carries this tenant through the runtime config so
    /// per-tenant secret URIs (e.g. `secrets://<env>/<tenant>/…`) resolve
    /// correctly. Requires no other routing flag — pair with `--path-prefix`
    /// or `--host` to make the deployment reachable.
    #[arg(long = "tenant", value_name = "TENANT")]
    pub tenant: Option<String>,
    /// Route binding: team id for `tenant_selector`. Defaults to `default`
    /// when `--tenant` is supplied without `--team`.
    #[arg(long = "team", value_name = "TEAM")]
    pub team: Option<String>,
}

#[derive(Args, Debug)]
pub struct TrafficTargetArgs {
    /// Environment id, e.g. `local`.
    pub env_id: Option<String>,
    /// Deployment ULID.
    #[arg(long)]
    pub deployment: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum ConfigVerb {
    Show,
    Set,
}

#[derive(Subcommand, Debug)]
pub enum CredentialsVerb {
    Requirements,
    Bootstrap,
    Rotate,
}

#[derive(Subcommand, Debug)]
pub enum SecretsVerb {
    List,
    Put,
    Get,
    Rotate,
}

#[derive(Args, Debug)]
pub struct PayloadArg {
    /// Inline payload as a JSON string. Mutually exclusive with `--answers`.
    #[arg(long, conflicts_with = "answers")]
    pub payload_json: Option<String>,
}

/// Build a [`LocalFsStore`] honoring `--store-root`, falling back to the
/// per-user default.
pub fn build_store(cmd: &OpCommand) -> Result<LocalFsStore, OpError> {
    let root = match &cmd.store_root {
        Some(p) => p.clone(),
        None => LocalFsStore::default_root().ok_or_else(|| {
            OpError::InvalidArgument("no --store-root and HOME / USERPROFILE not set".to_string())
        })?,
    };
    Ok(LocalFsStore::new(root))
}

/// Print an `OpOutcome` to stdout as compact JSON and return `Ok(())`.
pub fn print_outcome(outcome: &OpOutcome) -> Result<(), OpError> {
    let value = serde_json::to_value(outcome)
        .map_err(|e| OpError::InvalidArgument(format!("serialize outcome: {e}")))?;
    println!("{value}");
    Ok(())
}

/// Print a typed error in the JSON envelope and return the same error so
/// the caller can map it to the process exit code.
pub fn print_error(noun: &'static str, op: &'static str, err: &OpError) {
    let value = render_error(noun, op, err);
    eprintln!("{value}");
}

/// Top-level dispatcher. The verb modules each load their own payload via
/// `--answers` or `--payload-json`; this function only routes argv into
/// the right library call.
///
/// Uses the built-in env-pack registry (five default `local` handlers).
/// Phase D plug-ins that register additional handlers should call
/// [`dispatch_op_with_registry`] instead, passing a registry populated
/// with both built-ins and their plug-in handlers.
///
/// On success, the per-verb result is written to stdout as the documented
/// `{op, noun, result}` envelope. On error, the documented
/// `{op, noun, error: {kind, message}}` envelope is written to stderr and
/// the same `OpError` is returned so callers can map it to a process exit
/// code without re-rendering. Stdout and stderr never cross-contaminate.
pub fn dispatch_op(cmd: OpCommand) -> Result<(), OpError> {
    let registry = crate::env_packs::EnvPackRegistry::with_builtins();
    dispatch_op_with_registry(cmd, &registry)
}

/// Phase D plug-in entry point — register handlers on the registry, then
/// call this. The `credentials` noun (and any future noun that resolves
/// handlers through the registry) will see every handler the caller
/// registered.
pub fn dispatch_op_with_registry(
    cmd: OpCommand,
    registry: &crate::env_packs::EnvPackRegistry,
) -> Result<(), OpError> {
    let flags = OpFlags {
        schema_only: cmd.schema,
        answers: cmd.answers.clone(),
    };
    let (noun, verb) = noun_verb_labels(&cmd.noun);

    // Remote store selection (PR-3c). --store-url / GREENTIC_STORE_URL picks
    // the A8 HTTP backend. Schema-only requests stay local (schema is
    // store-independent and never touches the FS), so the operator can
    // inspect payloads without a running server.
    //
    // URL and token are paired by ORIGIN: an env-configured
    // GREENTIC_STORE_TOKEN must not leak to an ad-hoc `--store-url` flag
    // endpoint. A flag URL only accepts a flag token; an env URL accepts a
    // flag token or the env token.
    let (store_url, store_token) = crate::cli::dispatch_remote::resolve_remote_target(
        cmd.store_url.clone(),
        cmd.store_token.clone(),
        std::env::var("GREENTIC_STORE_URL").ok(),
        std::env::var("GREENTIC_STORE_TOKEN").ok(),
    );
    if let Some(raw_url) = store_url
        && !cmd.schema
    {
        return crate::cli::dispatch_remote::dispatch_op_remote(&raw_url, store_token, cmd, &flags)
            .inspect_err(|err| print_error(noun, verb, err));
    }

    let store = build_store(&cmd).inspect_err(|err| print_error(noun, verb, err))?;
    let result = match cmd.noun {
        OpNoun::Env { verb } => dispatch_env(&store, &flags, verb),
        OpNoun::EnvPacks { verb } => dispatch_env_packs(&store, &flags, verb),
        OpNoun::Bundles { verb } => dispatch_bundles(&store, &flags, verb),
        OpNoun::Revisions { verb } => dispatch_revisions(&store, &flags, verb),
        OpNoun::Traffic { verb } => dispatch_traffic(&store, &flags, verb),
        OpNoun::Deploy(args) => dispatch_deploy(&store, &flags, args),
        OpNoun::Config { verb } => dispatch_config(&store, &flags, verb),
        OpNoun::Credentials { verb } => dispatch_credentials(&store, registry, &flags, verb),
        OpNoun::Secrets { verb } => dispatch_secrets(&store, &flags, verb),
        OpNoun::TrustRoot { verb } => dispatch_trust_root(&store, &flags, verb),
        OpNoun::Messaging { verb } => dispatch_messaging(&store, &flags, verb),
        OpNoun::Extensions { verb } => dispatch_extensions(&store, &flags, verb),
    };
    result.inspect_err(|err| print_error(noun, verb, err))
}

/// Map an [`OpNoun`] to its `(noun, verb)` static label pair for envelope
/// rendering. Kept in lockstep with the verb enums above; adding a new
/// noun/verb requires extending the match here too.
pub fn noun_verb_labels(noun: &OpNoun) -> (&'static str, &'static str) {
    match noun {
        OpNoun::Env { verb } => (
            "env",
            match verb {
                EnvVerb::Init(_) => "init",
                EnvVerb::Apply(_) => "apply",
                EnvVerb::Create(_) => "create",
                EnvVerb::Update(_) => "update",
                EnvVerb::SetPublicUrl(_) => "set-public-url",
                EnvVerb::List => "list",
                EnvVerb::Show { .. } => "show",
                EnvVerb::Doctor { .. } => "doctor",
                EnvVerb::ToolCheck { .. } => "tool-check",
                EnvVerb::Destroy { .. } => "destroy",
                EnvVerb::MigrateDev { .. } => "migrate-dev",
                EnvVerb::MigrateState { .. } => "migrate-state",
            },
        ),
        OpNoun::EnvPacks { verb } => (
            "env-packs",
            match verb {
                EnvPacksVerb::Add => "add",
                EnvPacksVerb::Update => "update",
                EnvPacksVerb::Remove => "remove",
                EnvPacksVerb::Rollback => "rollback",
                EnvPacksVerb::List { .. } => "list",
            },
        ),
        OpNoun::Bundles { verb } => (
            "bundles",
            match verb {
                BundlesVerb::Add => "add",
                BundlesVerb::Update => "update",
                BundlesVerb::Remove => "remove",
                BundlesVerb::List { .. } => "list",
            },
        ),
        OpNoun::Revisions { verb } => (
            "revisions",
            match verb {
                RevisionsVerb::Stage(_) => "stage",
                RevisionsVerb::Warm => "warm",
                RevisionsVerb::Drain => "drain",
                RevisionsVerb::Archive => "archive",
                RevisionsVerb::List { .. } => "list",
            },
        ),
        OpNoun::Traffic { verb } => (
            "traffic",
            match verb {
                TrafficVerb::Set(_) => "set",
                TrafficVerb::Show(_) => "show",
                TrafficVerb::Rollback(_) => "rollback",
            },
        ),
        OpNoun::Deploy(_) => ("deploy", "run"),
        OpNoun::Config { verb } => (
            "config",
            match verb {
                ConfigVerb::Show => "show",
                ConfigVerb::Set => "set",
            },
        ),
        OpNoun::Credentials { verb } => (
            "credentials",
            match verb {
                CredentialsVerb::Requirements => "requirements",
                CredentialsVerb::Bootstrap => "bootstrap",
                CredentialsVerb::Rotate => "rotate",
            },
        ),
        OpNoun::Secrets { verb } => (
            "secrets",
            match verb {
                SecretsVerb::List => "list",
                SecretsVerb::Put => "put",
                SecretsVerb::Get => "get",
                SecretsVerb::Rotate => "rotate",
            },
        ),
        OpNoun::TrustRoot { verb } => (
            "trust-root",
            match verb {
                TrustRootVerb::Bootstrap { .. } => "bootstrap",
                TrustRootVerb::List { .. } => "list",
                TrustRootVerb::Add(_) => "add",
                TrustRootVerb::Remove(_) => "remove",
            },
        ),
        OpNoun::Messaging { verb } => (
            "messaging.endpoint",
            match verb {
                MessagingNoun::Endpoint { verb } => match verb {
                    MessagingEndpointVerb::Add(_) => "add",
                    MessagingEndpointVerb::List { .. } => "list",
                    MessagingEndpointVerb::Show { .. } => "show",
                    MessagingEndpointVerb::LinkBundle(_) => "link-bundle",
                    MessagingEndpointVerb::UnlinkBundle(_) => "unlink-bundle",
                    MessagingEndpointVerb::SetWelcomeFlow(_) => "set-welcome-flow",
                    MessagingEndpointVerb::Remove(_) => "remove",
                    MessagingEndpointVerb::RotateWebhookSecret(_) => "rotate-webhook-secret",
                },
            },
        ),
        OpNoun::Extensions { verb } => (
            "extensions",
            match verb {
                ExtensionsVerb::Add => "add",
                ExtensionsVerb::Update => "update",
                ExtensionsVerb::Remove => "remove",
                ExtensionsVerb::Rollback => "rollback",
                ExtensionsVerb::List { .. } => "list",
            },
        ),
    }
}

fn dispatch_env(store: &LocalFsStore, flags: &OpFlags, verb: EnvVerb) -> Result<(), OpError> {
    let outcome = match verb {
        EnvVerb::Init(args) => super::env::init(store, flags, args.into_payload(flags)?)?,
        EnvVerb::Apply(args) => {
            super::env_apply::apply(store, flags, args.mode(), args.updated_by, args.yes)?
        }
        EnvVerb::Create(args) => {
            super::env::create(store, flags, args.into_payload("create", flags)?)?
        }
        EnvVerb::Update(args) => {
            super::env::update(store, flags, args.into_payload("update", flags)?)?
        }

        EnvVerb::SetPublicUrl(args) => {
            super::env::set_public_url(store, flags, &args.env_id, &args.url)?
        }
        EnvVerb::List => super::env::list(store, flags)?,
        EnvVerb::Show { env_id } => super::env::show(store, flags, &env_id)?,
        EnvVerb::Doctor { env_id } => super::env::doctor(store, flags, &env_id)?,
        EnvVerb::ToolCheck { env_id } => super::env::tool_check(store, flags, &env_id)?,
        EnvVerb::Destroy { env_id, confirm } => {
            super::env::destroy(store, flags, &env_id, confirm)?
        }
        EnvVerb::MigrateDev {
            target,
            check,
            apply,
        } => {
            if !(check ^ apply) {
                return Err(OpError::InvalidArgument(
                    "migrate-dev requires exactly one of --check or --apply".to_string(),
                ));
            }
            if check {
                super::migrate::check(store, flags, &target)?
            } else {
                super::migrate::apply(store, flags, &target)?
            }
        }
        EnvVerb::MigrateState {
            target,
            check,
            apply,
            state_dir,
        } => {
            if !(check ^ apply) {
                return Err(OpError::InvalidArgument(
                    "migrate-state requires exactly one of --check or --apply".to_string(),
                ));
            }
            if check {
                super::migrate_state::check(store, flags, &target, state_dir.as_deref())?
            } else {
                super::migrate_state::apply(store, flags, &target, state_dir.as_deref())?
            }
        }
    };
    print_outcome(&outcome)
}

fn dispatch_env_packs(
    store: &LocalFsStore,
    flags: &OpFlags,
    verb: EnvPacksVerb,
) -> Result<(), OpError> {
    let outcome = match verb {
        EnvPacksVerb::Add => super::env_packs::add(store, flags, None)?,
        EnvPacksVerb::Update => super::env_packs::update(store, flags, None)?,
        EnvPacksVerb::Remove => super::env_packs::remove(store, flags, None)?,
        EnvPacksVerb::Rollback => super::env_packs::rollback(store, flags, None)?,
        EnvPacksVerb::List { env_id } => super::env_packs::list(store, flags, &env_id)?,
    };
    print_outcome(&outcome)
}

fn dispatch_extensions(
    store: &LocalFsStore,
    flags: &OpFlags,
    verb: ExtensionsVerb,
) -> Result<(), OpError> {
    let outcome = match verb {
        ExtensionsVerb::Add => super::extensions::add(store, flags, None)?,
        ExtensionsVerb::Update => super::extensions::update(store, flags, None)?,
        ExtensionsVerb::Remove => super::extensions::remove(store, flags, None)?,
        ExtensionsVerb::Rollback => super::extensions::rollback(store, flags, None)?,
        ExtensionsVerb::List { env_id } => super::extensions::list(store, flags, &env_id)?,
    };
    print_outcome(&outcome)
}

fn dispatch_bundles(
    store: &LocalFsStore,
    flags: &OpFlags,
    verb: BundlesVerb,
) -> Result<(), OpError> {
    let outcome = match verb {
        BundlesVerb::Add => super::bundles::add(store, flags, None)?,
        BundlesVerb::Update => super::bundles::update(store, flags, None)?,
        BundlesVerb::Remove => super::bundles::remove(store, flags, None)?,
        BundlesVerb::List { env_id } => super::bundles::list(store, flags, &env_id)?,
    };
    print_outcome(&outcome)
}

fn dispatch_revisions(
    store: &LocalFsStore,
    flags: &OpFlags,
    verb: RevisionsVerb,
) -> Result<(), OpError> {
    let outcome = match verb {
        RevisionsVerb::Stage(args) => {
            let payload = super::revisions::payload_from_stage_args(args)?;
            super::revisions::stage(store, flags, payload)?
        }
        RevisionsVerb::Warm => super::revisions::warm(store, flags, None)?,
        RevisionsVerb::Drain => super::revisions::drain(store, flags, None)?,
        RevisionsVerb::Archive => super::revisions::archive(store, flags, None)?,
        RevisionsVerb::List { env_id } => super::revisions::list(store, flags, &env_id)?,
    };
    print_outcome(&outcome)
}

fn dispatch_traffic(
    store: &LocalFsStore,
    flags: &OpFlags,
    verb: TrafficVerb,
) -> Result<(), OpError> {
    let outcome = match verb {
        TrafficVerb::Set(args) => {
            let payload = super::traffic::payload_from_set_args(args)?;
            super::traffic::set(store, flags, payload)?
        }
        TrafficVerb::Show(args) => {
            let payload = super::traffic::payload_from_target_args(args)?;
            super::traffic::show(store, flags, payload)?
        }
        TrafficVerb::Rollback(args) => {
            let payload = super::traffic::payload_from_target_args(args)?;
            super::traffic::rollback(store, flags, payload)?
        }
    };
    print_outcome(&outcome)
}

fn dispatch_deploy(
    store: &LocalFsStore,
    flags: &OpFlags,
    args: BundleDeployArgs,
) -> Result<(), OpError> {
    let payload = super::deploy::payload_from_deploy_args(args)?;
    let outcome = super::deploy::deploy(store, flags, payload)?;
    print_outcome(&outcome)
}

fn dispatch_config(store: &LocalFsStore, flags: &OpFlags, verb: ConfigVerb) -> Result<(), OpError> {
    let outcome = match verb {
        ConfigVerb::Show => super::config::show(store, flags, None)?,
        ConfigVerb::Set => super::config::set(store, flags, None)?,
    };
    print_outcome(&outcome)
}

fn dispatch_credentials(
    store: &LocalFsStore,
    registry: &crate::env_packs::EnvPackRegistry,
    flags: &OpFlags,
    verb: CredentialsVerb,
) -> Result<(), OpError> {
    let outcome = match verb {
        CredentialsVerb::Requirements => {
            super::credentials::requirements(store, registry, flags, None)?
        }
        CredentialsVerb::Bootstrap => super::credentials::bootstrap(store, registry, flags, None)?,
        CredentialsVerb::Rotate => super::credentials::rotate(store, registry, flags, None)?,
    };
    print_outcome(&outcome)
}

fn dispatch_secrets(
    store: &LocalFsStore,
    flags: &OpFlags,
    verb: SecretsVerb,
) -> Result<(), OpError> {
    let outcome = match verb {
        SecretsVerb::List => super::secrets::list(store, flags, None)?,
        SecretsVerb::Put => super::secrets::put(store, flags, None)?,
        SecretsVerb::Get => super::secrets::get(store, flags, None)?,
        SecretsVerb::Rotate => super::secrets::rotate(store, flags, None)?,
    };
    print_outcome(&outcome)
}

fn dispatch_trust_root(
    store: &LocalFsStore,
    flags: &OpFlags,
    verb: TrustRootVerb,
) -> Result<(), OpError> {
    let outcome = match verb {
        TrustRootVerb::Bootstrap { env_id } => {
            let payload = env_id
                .map(|id| super::trust_root::TrustRootBootstrapPayload { environment_id: id });
            super::trust_root::bootstrap(store, flags, payload)?
        }
        TrustRootVerb::List { env_id } => super::trust_root::list(store, flags, &env_id)?,
        TrustRootVerb::Add(args) => {
            let payload = match (args.env_id, args.key_id) {
                (Some(env_id), Some(key_id)) => Some(super::trust_root::TrustRootAddPayload {
                    environment_id: env_id,
                    key_id,
                    public_key_pem: args.public_key_pem,
                    public_key_file: args.public_key_file,
                }),
                _ => None, // fall through to --answers / --schema
            };
            super::trust_root::add(store, flags, payload)?
        }
        TrustRootVerb::Remove(args) => {
            let payload = match (args.env_id, args.key_id) {
                (Some(env_id), Some(key_id)) => Some(super::trust_root::TrustRootRemovePayload {
                    environment_id: env_id,
                    key_id,
                }),
                _ => None,
            };
            super::trust_root::remove(store, flags, payload)?
        }
    };
    print_outcome(&outcome)
}

fn dispatch_messaging(
    store: &LocalFsStore,
    flags: &OpFlags,
    verb: MessagingNoun,
) -> Result<(), OpError> {
    let outcome = match verb {
        MessagingNoun::Endpoint { verb } => match verb {
            MessagingEndpointVerb::Add(args) => {
                super::messaging::add(store, flags, args.into_payload("add", flags)?)?
            }
            MessagingEndpointVerb::List { env_id } => {
                super::messaging::list(store, flags, &env_id)?
            }
            MessagingEndpointVerb::Show {
                env_id,
                endpoint_id,
            } => super::messaging::show(store, flags, &env_id, &endpoint_id)?,
            MessagingEndpointVerb::LinkBundle(args) => super::messaging::link_bundle(
                store,
                flags,
                args.into_payload("link-bundle", flags)?,
            )?,
            MessagingEndpointVerb::UnlinkBundle(args) => super::messaging::unlink_bundle(
                store,
                flags,
                args.into_payload("unlink-bundle", flags)?,
            )?,
            MessagingEndpointVerb::SetWelcomeFlow(args) => super::messaging::set_welcome_flow(
                store,
                flags,
                args.into_payload("set-welcome-flow", flags)?,
            )?,
            MessagingEndpointVerb::Remove(args) => {
                super::messaging::remove(store, flags, args.into_remove_payload("remove", flags)?)?
            }
            MessagingEndpointVerb::RotateWebhookSecret(args) => {
                super::messaging::rotate_webhook_secret(
                    store,
                    flags,
                    args.into_rotate_payload("rotate-webhook-secret", flags)?,
                )?
            }
        },
    };
    print_outcome(&outcome)
}

/// Silence the `CapabilitySlot` re-export warning while preserving the symbol
/// for downstream noun modules that take a slot positional in future work.
#[allow(dead_code)]
fn _slot_anchor(_: CapabilitySlot) {}
