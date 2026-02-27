use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, anyhow};
use clap::{Args, Parser, Subcommand, ValueHint};
use serde_json::json;

#[derive(Parser, Debug)]
#[command(name = "greentic-deployer-packgen")]
#[command(about = "Deterministic generator for deployer provider packs")]
struct Cli {
    #[command(subcommand)]
    command: PackgenCommand,
}

#[derive(Subcommand, Debug)]
enum PackgenCommand {
    /// Generate a deployer provider pack for a given provider.
    Generate(GenerateArgs),
}

#[derive(Args, Debug, Clone)]
struct GenerateArgs {
    /// Provider identifier (e.g. aws, local).
    #[arg(long)]
    provider: String,

    /// Directory that should contain the generated provider pack sources.
    #[arg(long, default_value = "providers/deployer", value_hint = ValueHint::DirPath)]
    out: PathBuf,

    /// Output directory for built .gtpack archives.
    #[arg(long, default_value = "dist", value_hint = ValueHint::DirPath)]
    dist: PathBuf,

    /// Pack id to emit (default `greentic.demo.deploy.<provider>`).
    #[arg(long)]
    pack_id: Option<String>,

    /// Emit verbose diagnostics when running each CLI.
    #[arg(long)]
    verbose: bool,

    /// Print the command sequence without executing it.
    #[arg(long)]
    dry_run: bool,

    /// Require the validator to report full success before proceeding.
    #[arg(long)]
    strict: bool,

    /// Validator pack reference used by greentic-pack doctor.
    #[arg(
        long,
        default_value = "oci://ghcr.io/greenticai/validators/deployer:latest"
    )]
    validator_pack: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        PackgenCommand::Generate(args) => Packgen::new(args).run(),
    }
}

struct Packgen {
    args: GenerateArgs,
}

impl Packgen {
    fn new(args: GenerateArgs) -> Self {
        Self { args }
    }

    fn run(&self) -> Result<()> {
        let context = PackContext::new(&self.args);
        if !self.args.dry_run {
            self.prepare_workspace(&context)?;
        }

        self.execute_commands(&context.initial_commands())?;

        if !self.args.dry_run {
            generate_flow(&context.flow_path, &context.flow_id, &context.provider)?;
        }

        self.execute_commands(&context.late_commands())?;

        if self.args.strict && !self.args.dry_run {
            println!(
                "strict validation requested; greentic-pack doctor already ran with --validate"
            );
        }

        Ok(())
    }

    fn prepare_workspace(&self, context: &PackContext) -> Result<()> {
        if self.args.dry_run {
            return Ok(());
        }

        fs::create_dir_all(&self.args.out)
            .with_context(|| format!("create out directory {}", self.args.out.display()))?;
        fs::create_dir_all(&context.dist_dir)
            .with_context(|| format!("create dist directory {}", context.dist_dir.display()))?;

        if context.pack_dir.exists() {
            fs::remove_dir_all(&context.pack_dir)?;
        }
        if context.gtpack_path.exists() {
            fs::remove_file(&context.gtpack_path)?;
        }

        Ok(())
    }

    fn execute_commands(&self, commands: &[PackCommand]) -> Result<()> {
        for command in commands {
            if self.args.verbose || self.args.dry_run {
                println!("> {}", command.formatted());
            }
            if self.args.dry_run {
                continue;
            }
            command.execute()?;
        }
        Ok(())
    }
}

const PLACEHOLDER_NODE_ID: &str = "emit_placeholder";
const PLACEHOLDER_COMPONENT_ID: &str = "greentic.host.iac-write-files";
const PLACEHOLDER_STORE_REF: &str = "greentic.host/iac-write-files@1.0.0";
const PLACEHOLDER_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

struct PackContext {
    provider: String,
    pack_id: String,
    pack_dir: PathBuf,
    flows_dir: PathBuf,
    flow_id: String,
    flow_path: PathBuf,
    dist_dir: PathBuf,
    gtpack_path: PathBuf,
    extension_id: String,
    validator_pack: String,
}

impl PackContext {
    fn new(args: &GenerateArgs) -> Self {
        let provider = args.provider.trim().to_lowercase();
        let pack_id = args
            .pack_id
            .clone()
            .unwrap_or_else(|| format!("greentic.demo.deploy.{provider}"));
        let pack_dir = args.out.join(&provider);
        let flows_dir = pack_dir.join("flows");
        let flow_id = format!("deploy_{provider}_iac");
        let flow_path = flows_dir.join(format!("{flow_id}.ygtc"));
        let dist_dir = args.dist.clone();
        let gtpack_name = pack_id.replace('.', "-");
        let gtpack_path = dist_dir.join(format!("{gtpack_name}.gtpack"));
        let extension_id = format!("deployer.{provider}");
        Self {
            provider,
            pack_id,
            pack_dir,
            flows_dir,
            flow_id,
            flow_path,
            dist_dir,
            gtpack_path,
            extension_id,
            validator_pack: args.validator_pack.clone(),
        }
    }

    fn initial_commands(&self) -> Vec<PackCommand> {
        let pack_dir = self.pack_dir.to_string_lossy().to_string();
        let flow_path = self.flow_path.to_string_lossy().to_string();
        vec![
            PackCommand::new("greentic-pack", ["new", &self.pack_id, "--dir", &pack_dir]),
            PackCommand::new(
                "greentic-flow",
                [
                    "new",
                    "--flow",
                    &flow_path,
                    "--id",
                    &self.flow_id,
                    "--type",
                    "component-config",
                    "--schema-version",
                    "2",
                    "--force",
                ],
            ),
        ]
    }

    fn late_commands(&self) -> Vec<PackCommand> {
        let pack_dir = self.pack_dir.to_string_lossy().to_string();
        let flows_dir = self.flows_dir.to_string_lossy().to_string();
        let gtpack_path = self.gtpack_path.to_string_lossy().to_string();
        vec![
            PackCommand::new("greentic-flow", ["doctor", &flows_dir]),
            PackCommand::new(
                "greentic-pack",
                [
                    "add-extension",
                    "provider",
                    "--pack-dir",
                    &pack_dir,
                    "--id",
                    &self.extension_id,
                    "--kind",
                    "deployment",
                    "--flow",
                    &self.flow_id,
                ],
            ),
            PackCommand::new("greentic-pack", ["update", "--in", &pack_dir]),
            PackCommand::new("greentic-pack", ["resolve", "--in", &pack_dir]),
            PackCommand::new(
                "greentic-pack",
                ["build", "--in", &pack_dir, "--gtpack-out", &gtpack_path],
            ),
            PackCommand::new(
                "greentic-pack",
                [
                    "doctor",
                    "--pack",
                    &gtpack_path,
                    "--validate",
                    "--validator-pack",
                    &self.validator_pack,
                ],
            ),
        ]
    }
}

struct PackCommand {
    program: &'static str,
    args: Vec<String>,
}

impl PackCommand {
    fn new<I, S>(program: &'static str, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            program,
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    fn formatted(&self) -> String {
        let mut parts = vec![self.program.to_string()];
        parts.extend(self.args.clone());
        parts.join(" ")
    }

    fn execute(&self) -> Result<()> {
        let mut command = Command::new(self.program);
        command.args(&self.args);
        let status = command
            .status()
            .with_context(|| format!("failed to execute {}", self.program))?;
        if !status.success() {
            return Err(anyhow!("{} exited with {}", self.program, status));
        }
        Ok(())
    }
}

fn generate_flow(flow_path: &Path, flow_id: &str, provider: &str) -> Result<()> {
    let content = format!(
        r#"id: deploy_{provider}_iac
type: component-config
start: emit_placeholder
parameters: {{}}
tags: []
schema_version: 2
entrypoints:
  default:
    - emit_placeholder
nodes:
  emit_placeholder:
    greentic.host.iac-write-files.write-files:
      files:
        - path: README.md
          overwrite: false
          content: |
            # Placeholder deployment artifacts

            Generated for provider `{provider}`.
        - path: iac.placeholder
          overwrite: true
          content: |
            provider: {provider}
            summary: placeholder iac file
    routing:
      - out: true
"#,
        provider = provider
    );

    fs::write(flow_path, content).with_context(|| format!("write flow {}", flow_path.display()))?;
    write_flow_resolve_sidecars(flow_path, flow_id)?;
    Ok(())
}

fn write_flow_resolve_sidecars(flow_path: &Path, flow_id: &str) -> Result<()> {
    let sidecar_path = flow_path.with_extension("ygtc.resolve.json");
    let summary_path = flow_path.with_extension("ygtc.resolve.summary.json");
    let sidecar_flow = format!("flows/{}.ygtc", flow_id);
    let summary_flow = format!("{}.ygtc", flow_id);

    let sidecar_doc = json!({
        "schema_version": 1,
        "flow": sidecar_flow,
        "nodes": {
            PLACEHOLDER_NODE_ID: {
                "source": {
                    "kind": "store",
                    "ref": format!("store://{}", PLACEHOLDER_STORE_REF),
                    "digest": PLACEHOLDER_DIGEST,
                }
            }
        }
    });

    fs::write(&sidecar_path, serde_json::to_string_pretty(&sidecar_doc)?)
        .with_context(|| format!("write resolve sidecar {}", sidecar_path.display()))?;

    let summary_doc = json!({
        "schema_version": 1,
        "flow": summary_flow,
        "nodes": {
            PLACEHOLDER_NODE_ID: {
                "component_id": PLACEHOLDER_COMPONENT_ID,
                "source": {
                    "kind": "store",
                    "ref": PLACEHOLDER_STORE_REF,
                },
                "digest": PLACEHOLDER_DIGEST,
            }
        }
    });

    fs::write(&summary_path, serde_json::to_string_pretty(&summary_doc)?)
        .with_context(|| format!("write resolve summary {}", summary_path.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample_args() -> GenerateArgs {
        GenerateArgs {
            provider: "local".into(),
            out: PathBuf::from("providers/deployer"),
            dist: PathBuf::from("dist"),
            pack_id: None,
            verbose: false,
            dry_run: true,
            strict: false,
            validator_pack: "oci://ghcr.io/greenticai/validators/deployer:latest".into(),
        }
    }

    #[test]
    fn command_sequence_captures_expected_steps() {
        let args = sample_args();
        let context = PackContext::new(&args);
        let initial = context.initial_commands();
        assert_eq!(initial.len(), 2);
        assert_eq!(initial[0].program, "greentic-pack");
        assert!(initial[0].formatted().contains("new"));
        assert_eq!(initial[1].program, "greentic-flow");
        let late = context.late_commands();
        assert!(late.iter().any(|cmd| cmd.program == "greentic-flow"));
        assert!(late.iter().any(|cmd| cmd.program == "greentic-pack"));
        assert!(late.last().unwrap().formatted().contains("--validate"));
    }
}

