use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use crate::ext::errors::ExtensionResult;
use crate::ext::loader::{resolve_extension_dir, scan};
use crate::ext::registry::ExtensionRegistry;

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
}

pub fn run(cmd: ExtCommand) -> ExtensionResult<()> {
    let dir = resolve_extension_dir(cmd.ext_dir.as_deref());
    match cmd.command {
        ExtSubcommand::List => run_list(&dir),
        ExtSubcommand::Info { ext_id } => run_info(&dir, &ext_id),
        ExtSubcommand::Validate { dir: target } => run_validate(&target),
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
        .ok_or_else(|| crate::ext::errors::ExtensionError::TargetNotFound(ext_id.into()))?;
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
        return Err(crate::ext::errors::ExtensionError::DirNotFound(dir.into()));
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
