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
/// passthrough is wired in a follow-up PR.
#[derive(Parser, Debug)]
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
    Create,
    Update,
    List,
    Show {
        env_id: String,
    },
    Doctor {
        env_id: String,
    },
    Destroy {
        env_id: String,
        #[arg(long)]
        confirm: bool,
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
    Set,
    Show,
    Rollback,
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
pub fn dispatch_op(cmd: OpCommand) -> Result<(), OpError> {
    let flags = OpFlags {
        schema_only: cmd.schema,
        answers: cmd.answers.clone(),
    };
    let store = build_store(&cmd)?;
    match cmd.noun {
        OpNoun::Env { verb } => dispatch_env(&store, &flags, verb),
        OpNoun::EnvPacks { verb } => dispatch_env_packs(&store, &flags, verb),
        OpNoun::Bundles { verb } => dispatch_bundles(&store, &flags, verb),
        OpNoun::Revisions { verb } => dispatch_revisions(&store, &flags, verb),
        OpNoun::Traffic { verb } => dispatch_traffic(&store, &flags, verb),
        OpNoun::Config { verb } => dispatch_config(&store, &flags, verb),
        OpNoun::Credentials { verb } => dispatch_credentials(&store, &flags, verb),
        OpNoun::Secrets { verb } => dispatch_secrets(&store, &flags, verb),
    }
}

fn dispatch_env(store: &LocalFsStore, flags: &OpFlags, verb: EnvVerb) -> Result<(), OpError> {
    let outcome = match verb {
        EnvVerb::Create => super::env::create(store, flags, None)?,
        EnvVerb::Update => super::env::update(store, flags, None)?,
        EnvVerb::List => super::env::list(store, flags)?,
        EnvVerb::Show { env_id } => super::env::show(store, flags, &env_id)?,
        EnvVerb::Doctor { env_id } => super::env::doctor(store, flags, &env_id)?,
        EnvVerb::Destroy { env_id, confirm } => {
            super::env::destroy(store, flags, &env_id, confirm)?
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
        TrafficVerb::Set => super::traffic::set(store, flags, None)?,
        TrafficVerb::Show => super::traffic::show(store, flags, None)?,
        TrafficVerb::Rollback => super::traffic::rollback(store, flags, None)?,
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
