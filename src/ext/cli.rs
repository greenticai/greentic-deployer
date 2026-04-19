use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use crate::ext::backend_adapter::{ExtAction, run as run_adapter};
use crate::ext::dispatcher::{DispatchAction, DispatchInput, dispatch_extension};
use crate::ext::errors::{ExtensionError, ExtensionResult};
use crate::ext::loader::{resolve_extension_dir, scan};
use crate::ext::registry::ExtensionRegistry;
use crate::ext::wasm::WasmtimeInvoker;

#[derive(Parser)]
pub struct ExtCommand {
    /// Override the extension directory. Default: $GREENTIC_DEPLOY_EXT_DIR or
    /// ~/.greentic/extensions/deploy/.
    #[arg(long = "ext-dir", global = true)]
    pub ext_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: ExtSubcommand,
}

#[derive(Subcommand)]
pub enum ExtSubcommand {
    /// List loaded extensions and their contributed targets.
    List,
    /// Show metadata for one extension.
    Info { ext_id: String },
    /// Validate a describe.json + referenced wasm at the given path.
    Validate { dir: PathBuf },
    /// Apply an extension-contributed deploy target.
    Apply(ExtApplyArgs),
    /// Destroy an extension-contributed deploy target.
    Destroy(ExtDestroyArgs),
}

#[derive(Parser)]
pub struct ExtApplyArgs {
    /// Target id as declared by the extension (see `ext list`).
    #[arg(long)]
    pub target: String,
    /// Path to credentials JSON file.
    #[arg(long)]
    pub creds: PathBuf,
    /// Path to config JSON file.
    #[arg(long)]
    pub config: PathBuf,
    /// Optional pack path (required by some backends, e.g. cloud refs).
    #[arg(long)]
    pub pack: Option<PathBuf>,
    /// Treat validation warnings as errors.
    #[arg(long, default_value_t = false)]
    pub strict_validate: bool,
}

#[derive(Parser)]
pub struct ExtDestroyArgs {
    /// Target id as declared by the extension (see `ext list`).
    #[arg(long)]
    pub target: String,
    /// Path to credentials JSON file.
    #[arg(long)]
    pub creds: PathBuf,
    /// Path to config JSON file.
    #[arg(long)]
    pub config: PathBuf,
    /// Optional pack path (required by some backends, e.g. cloud refs).
    #[arg(long)]
    pub pack: Option<PathBuf>,
    /// Treat validation warnings as errors.
    #[arg(long, default_value_t = false)]
    pub strict_validate: bool,
}

pub fn run(cmd: ExtCommand) -> ExtensionResult<()> {
    let dir = resolve_extension_dir(cmd.ext_dir.as_deref());
    match cmd.command {
        ExtSubcommand::List => run_list(&dir),
        ExtSubcommand::Info { ext_id } => run_info(&dir, &ext_id),
        ExtSubcommand::Validate { dir: target } => run_validate(&target),
        ExtSubcommand::Apply(args) => run_apply(&dir, args),
        ExtSubcommand::Destroy(args) => run_destroy(&dir, args),
    }
}

fn run_list(dir: &Path) -> ExtensionResult<()> {
    let loaded = scan(dir)?;
    let reg = ExtensionRegistry::build(loaded);
    let mut targets: Vec<_> = reg.list().collect();
    targets.sort_by(|a, b| a.contribution.id.cmp(&b.contribution.id));
    println!("{:<30}  {:<30}  {:<30}", "TARGET", "EXTENSION", "EXECUTION");
    for t in targets {
        let exec = match &t.contribution.execution {
            crate::ext::describe::Execution::Builtin { backend, handler } => match handler {
                Some(h) => format!("builtin:{backend}:{h}"),
                None => format!("builtin:{backend}"),
            },
            crate::ext::describe::Execution::Wasm => "wasm".to_string(),
        };
        println!("{:<30}  {:<30}  {}", t.contribution.id, t.ext_id, exec);
    }
    if !reg.conflicts().is_empty() {
        eprintln!(
            "\nWARNING: {} target id conflict(s) detected.",
            reg.conflicts().len()
        );
        for c in reg.conflicts() {
            eprintln!("  {} provided by: {:?}", c.target_id, c.providers);
        }
    }
    Ok(())
}

fn run_info(dir: &Path, ext_id: &str) -> ExtensionResult<()> {
    let loaded = scan(dir)?;
    let ext = loaded
        .iter()
        .find(|e| e.describe.metadata.id == ext_id)
        .ok_or_else(|| ExtensionError::TargetNotFound(ext_id.into()))?;
    println!("id:      {}", ext.describe.metadata.id);
    println!("version: {}", ext.describe.metadata.version);
    println!("root:    {}", ext.root_dir.display());
    println!("wasm:    {}", ext.wasm_path.display());
    println!("targets:");
    for t in &ext.describe.contributions.targets {
        println!("  - {} ({})", t.id, t.display_name);
    }
    Ok(())
}

fn run_validate(dir: &Path) -> ExtensionResult<()> {
    let v = scan(dir)?;
    if v.is_empty() {
        return Err(ExtensionError::DirNotFound(dir.into()));
    }
    for ext in &v {
        println!(
            "OK  {} ({} targets)",
            ext.describe.metadata.id,
            ext.describe.contributions.targets.len()
        );
    }
    Ok(())
}

pub fn run_apply(dir: &Path, args: ExtApplyArgs) -> ExtensionResult<()> {
    let creds_json =
        std::fs::read_to_string(&args.creds).map_err(|source| ExtensionError::CredsReadError {
            path: args.creds.clone(),
            source,
        })?;
    let config_json = std::fs::read_to_string(&args.config).map_err(|source| {
        ExtensionError::ConfigReadError {
            path: args.config.clone(),
            source,
        }
    })?;

    let loaded = scan(dir)?;
    let reg = ExtensionRegistry::build(loaded);
    let invoker = WasmtimeInvoker::new(&[dir])?;
    let action = dispatch_extension(
        &reg,
        &invoker,
        DispatchInput {
            target_id: &args.target,
            creds_json: &creds_json,
            config_json: &config_json,
            strict_validate: args.strict_validate,
        },
    )?;
    match action {
        DispatchAction::Builtin(bridge) => run_adapter(
            bridge.backend,
            bridge.handler.as_deref(),
            ExtAction::Apply,
            &creds_json,
            &config_json,
            args.pack.as_deref(),
        ),
    }
}

pub fn run_destroy(dir: &Path, args: ExtDestroyArgs) -> ExtensionResult<()> {
    let creds_json =
        std::fs::read_to_string(&args.creds).map_err(|source| ExtensionError::CredsReadError {
            path: args.creds.clone(),
            source,
        })?;
    let config_json = std::fs::read_to_string(&args.config).map_err(|source| {
        ExtensionError::ConfigReadError {
            path: args.config.clone(),
            source,
        }
    })?;

    let loaded = scan(dir)?;
    let reg = ExtensionRegistry::build(loaded);
    let invoker = WasmtimeInvoker::new(&[dir])?;
    let action = dispatch_extension(
        &reg,
        &invoker,
        DispatchInput {
            target_id: &args.target,
            creds_json: &creds_json,
            config_json: &config_json,
            strict_validate: args.strict_validate,
        },
    )?;
    match action {
        DispatchAction::Builtin(bridge) => run_adapter(
            bridge.backend,
            bridge.handler.as_deref(),
            ExtAction::Destroy,
            &creds_json,
            &config_json,
            args.pack.as_deref(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_apply_missing_creds_file_errors_with_path() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.json");
        std::fs::write(&config_path, "{}").unwrap();
        let args = ExtApplyArgs {
            target: "x".into(),
            creds: tmp.path().join("does-not-exist.json"),
            config: config_path,
            pack: None,
            strict_validate: false,
        };
        let err = run_apply(tmp.path(), args).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("does-not-exist.json"), "got: {msg}");
    }

    #[test]
    fn run_apply_missing_config_file_errors_with_path() {
        let tmp = tempfile::tempdir().unwrap();
        let creds_path = tmp.path().join("creds.json");
        std::fs::write(&creds_path, "{}").unwrap();
        let args = ExtApplyArgs {
            target: "x".into(),
            creds: creds_path,
            config: tmp.path().join("missing-config.json"),
            pack: None,
            strict_validate: false,
        };
        let err = run_apply(tmp.path(), args).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("missing-config.json"), "got: {msg}");
    }

    #[test]
    fn run_destroy_missing_creds_file_errors_with_path() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.json");
        std::fs::write(&config_path, "{}").unwrap();
        let args = ExtDestroyArgs {
            target: "x".into(),
            creds: tmp.path().join("does-not-exist.json"),
            config: config_path,
            pack: None,
            strict_validate: false,
        };
        let err = run_destroy(tmp.path(), args).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("does-not-exist.json"), "got: {msg}");
    }
}
