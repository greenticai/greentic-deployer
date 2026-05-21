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
    after_help = "Nouns: env, env-packs, bundles, revisions, traffic, config, credentials, secrets.\n\
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
}

#[derive(Subcommand, Debug)]
pub enum EnvVerb {
    /// Idempotent bootstrap of the `local` environment with the five default
    /// env-pack bindings (A4 helper exposed as a CLI verb). Creates the env
    /// if missing, fills in any missing default bindings on an existing env,
    /// or reports `untouched` if the env is already complete. User-bound
    /// non-default descriptors are NEVER overwritten.
    Init,
    Create,
    Update,
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
pub enum EnvPacksVerb {
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
    Stage,
    Warm,
    Drain,
    Archive,
    List { env_id: String },
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
    /// Idempotency key — REQUIRED on the direct-args path. Re-running the
    /// same command with the same key is a no-op replay; a different key
    /// (or omitting it) is treated as a brand-new mutation and would
    /// snapshot the live split as the one-step rollback target, destroying
    /// the real pre-change rollback target. Use any stable string (ULID,
    /// UUID, ticket id) — the library never interprets it.
    #[arg(long)]
    pub idempotency_key: Option<String>,
    /// Actor recorded on the split. Defaults to `operator`.
    #[arg(long)]
    pub updated_by: Option<String>,
    /// Sidecar authorization-doc path. Defaults to `auth.json`.
    #[arg(long)]
    pub authorization_ref: Option<PathBuf>,
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
/// On success, the per-verb result is written to stdout as the documented
/// `{op, noun, result}` envelope. On error, the documented
/// `{op, noun, error: {kind, message}}` envelope is written to stderr and
/// the same `OpError` is returned so callers can map it to a process exit
/// code without re-rendering. Stdout and stderr never cross-contaminate.
pub fn dispatch_op(cmd: OpCommand) -> Result<(), OpError> {
    let flags = OpFlags {
        schema_only: cmd.schema,
        answers: cmd.answers.clone(),
    };
    let (noun, verb) = noun_verb_labels(&cmd.noun);
    let store = build_store(&cmd).inspect_err(|err| print_error(noun, verb, err))?;
    let result = match cmd.noun {
        OpNoun::Env { verb } => dispatch_env(&store, &flags, verb),
        OpNoun::EnvPacks { verb } => dispatch_env_packs(&store, &flags, verb),
        OpNoun::Bundles { verb } => dispatch_bundles(&store, &flags, verb),
        OpNoun::Revisions { verb } => dispatch_revisions(&store, &flags, verb),
        OpNoun::Traffic { verb } => dispatch_traffic(&store, &flags, verb),
        OpNoun::Config { verb } => dispatch_config(&store, &flags, verb),
        OpNoun::Credentials { verb } => dispatch_credentials(&store, &flags, verb),
        OpNoun::Secrets { verb } => dispatch_secrets(&store, &flags, verb),
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
                EnvVerb::Init => "init",
                EnvVerb::Create => "create",
                EnvVerb::Update => "update",
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
                RevisionsVerb::Stage => "stage",
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
    }
}

fn dispatch_env(store: &LocalFsStore, flags: &OpFlags, verb: EnvVerb) -> Result<(), OpError> {
    let outcome = match verb {
        EnvVerb::Init => super::env::init(store, flags)?,
        EnvVerb::Create => super::env::create(store, flags, None)?,
        EnvVerb::Update => super::env::update(store, flags, None)?,
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
        RevisionsVerb::Stage => super::revisions::stage(store, flags, None)?,
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

fn dispatch_config(store: &LocalFsStore, flags: &OpFlags, verb: ConfigVerb) -> Result<(), OpError> {
    let outcome = match verb {
        ConfigVerb::Show => super::config::show(store, flags, None)?,
        ConfigVerb::Set => super::config::set(store, flags, None)?,
    };
    print_outcome(&outcome)
}

fn dispatch_credentials(
    store: &LocalFsStore,
    flags: &OpFlags,
    verb: CredentialsVerb,
) -> Result<(), OpError> {
    let outcome = match verb {
        CredentialsVerb::Requirements => super::credentials::requirements(store, flags, None)?,
        CredentialsVerb::Bootstrap => super::credentials::bootstrap(store, flags, None)?,
        CredentialsVerb::Rotate => super::credentials::rotate(store, flags, None)?,
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

/// Silence the `CapabilitySlot` re-export warning while preserving the symbol
/// for downstream noun modules that take a slot positional in future work.
#[allow(dead_code)]
fn _slot_anchor(_: CapabilitySlot) {}
