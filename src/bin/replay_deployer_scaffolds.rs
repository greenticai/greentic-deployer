use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use greentic_deployer::contract::{DeployerContractV1, EXT_DEPLOYER_CONTRACT_V1};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use serde_yaml_bw as serde_yaml;

#[derive(Debug, Deserialize)]
struct ScaffoldIndex {
    schema_version: u32,
    answers: Vec<String>,
}

fn main() -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let required_tools = ["greentic-pack", "greentic-flow"];
    let missing_tools = required_tools
        .into_iter()
        .filter(|tool| !command_available(tool))
        .collect::<Vec<_>>();
    if !missing_tools.is_empty() {
        eprintln!(
            "skipping replay_deployer_scaffolds: missing external tool(s): {}",
            missing_tools.join(", ")
        );
        return Ok(());
    }

    let output_root = root.join("target/replayed-pack-scaffolds");
    recreate_dir(&output_root)?;

    let index: ScaffoldIndex =
        load_json(&root.join("testdata/answers/deployer-scaffolds/index.json"))?;
    ensure!(
        index.schema_version == 1,
        "unexpected scaffold index schema version"
    );

    for answer_ref in index.answers {
        let answer_path = root.join(&answer_ref);
        let fixture_name = answer_path
            .file_stem()
            .and_then(|name| name.to_str())
            .context("missing fixture name")?;
        let fixture_root = root.join("fixtures/packs").join(fixture_name);
        let pack_root = output_root.join(fixture_name);
        let materialized_answers = output_root.join(format!("{fixture_name}.answers.json"));

        materialize_answers(&answer_path, &materialized_answers, &pack_root)?;
        run_command(
            &root,
            "greentic-pack",
            &[
                "wizard",
                "validate",
                "--answers",
                materialized_answers.to_str().unwrap(),
            ],
        )?;

        run_command(
            &root,
            "greentic-pack",
            &[
                "wizard",
                "apply",
                "--answers",
                materialized_answers.to_str().unwrap(),
                "--emit-answers",
                materialized_answers.to_str().unwrap(),
            ],
        )?;

        let contract: DeployerContractV1 =
            load_json(&fixture_root.join("contract.greentic.deployer.v1.json"))?;
        sync_scaffold_flows(&root, &pack_root, &contract)?;
        overlay_fixture_content(&fixture_root, &pack_root)?;
        sync_pack_metadata(&pack_root, &contract)?;
        run_command_in_dir(&pack_root, "greentic-pack", &["doctor"])?;
        println!("replayed scaffold {}", pack_root.display());
    }

    Ok(())
}

fn command_available(program: &str) -> bool {
    // Accepted risk: callers pass fixed tool names from this maintenance binary, and no shell is used.
    // foxguard: ignore[rs/no-command-injection]
    match Command::new(program).arg("--help").output() {
        Ok(_) => true,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => true,
    }
}

fn recreate_dir(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_dir_all(path).with_context(|| format!("remove {}", path.display()))?;
    }
    fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
    Ok(())
}

fn materialize_answers(template: &Path, output: &Path, pack_root: &Path) -> Result<()> {
    let content =
        fs::read_to_string(template).with_context(|| format!("read {}", template.display()))?;
    let rendered = content.replace("__PACK_DIR__", &pack_root.display().to_string());
    fs::write(output, rendered).with_context(|| format!("write {}", output.display()))?;
    Ok(())
}

fn overlay_fixture_content(fixture_root: &Path, pack_root: &Path) -> Result<()> {
    for entry in
        fs::read_dir(fixture_root).with_context(|| format!("read {}", fixture_root.display()))?
    {
        let entry = entry?;
        let source = entry.path();
        let target = pack_root.join(entry.file_name());
        if source.is_dir() {
            copy_tree(&source, &target)?;
        } else if source.is_file() {
            copy_if_exists(&source, &target)?;
        }
    }
    Ok(())
}

fn sync_pack_metadata(pack_root: &Path, contract: &DeployerContractV1) -> Result<()> {
    let pack_yaml = pack_root.join("pack.yaml");
    let content =
        fs::read_to_string(&pack_yaml).with_context(|| format!("read {}", pack_yaml.display()))?;
    let mut document: JsonValue =
        serde_yaml::from_str(&content).with_context(|| format!("parse {}", pack_yaml.display()))?;
    if let Some(mapping) = document.as_object_mut() {
        mapping.insert(
            "version".to_string(),
            JsonValue::String(env!("CARGO_PKG_VERSION").to_string()),
        );
    }
    let contract_extension = serde_json::json!({
        "kind": EXT_DEPLOYER_CONTRACT_V1,
        "version": "1.0.0",
        "inline": contract,
    });
    let extensions = document
        .pointer_mut("/extensions")
        .and_then(JsonValue::as_object_mut)
        .context("missing extensions mapping")?;
    extensions.insert(EXT_DEPLOYER_CONTRACT_V1.to_string(), contract_extension);
    let updated = serde_yaml::to_string(&document).context("render pack.yaml")?;
    fs::write(&pack_yaml, updated).with_context(|| format!("write {}", pack_yaml.display()))?;
    Ok(())
}

fn copy_if_exists(src: &Path, dest: &Path) -> Result<()> {
    if !src.exists() {
        return Ok(());
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::copy(src, dest).with_context(|| format!("copy {} -> {}", src.display(), dest.display()))?;
    Ok(())
}

fn copy_tree(src: &Path, dest: &Path) -> Result<()> {
    if !src.exists() {
        return Ok(());
    }
    fs::create_dir_all(dest).with_context(|| format!("create {}", dest.display()))?;
    for entry in fs::read_dir(src).with_context(|| format!("read {}", src.display()))? {
        let entry = entry?;
        let path = entry.path();
        let target = dest.join(entry.file_name());
        if path.is_dir() {
            copy_tree(&path, &target)?;
        } else if path.is_file() {
            copy_if_exists(&path, &target)?;
        }
    }
    Ok(())
}

fn sync_scaffold_flows(root: &Path, pack_root: &Path, contract: &DeployerContractV1) -> Result<()> {
    let mut desired = BTreeMap::new();
    desired.insert("plan".to_string(), contract.planner.flow_id.clone());
    for capability in &contract.capabilities {
        desired.insert(
            capability.capability.as_str().to_string(),
            capability.flow_id.clone(),
        );
    }

    for (generic_name, target_flow_id) in desired {
        let current_flow = pack_root.join("flows").join(format!("{generic_name}.ygtc"));
        if !current_flow.exists() {
            continue;
        }
        run_command(
            root,
            "greentic-flow",
            &[
                "update",
                "--flow",
                current_flow.to_str().unwrap(),
                "--id",
                &target_flow_id,
                "--name",
                &target_flow_id,
            ],
        )?;

        let target_flow = pack_root
            .join("flows")
            .join(format!("{target_flow_id}.ygtc"));
        if current_flow != target_flow {
            fs::rename(&current_flow, &target_flow).with_context(|| {
                format!(
                    "rename flow {} -> {}",
                    current_flow.display(),
                    target_flow.display()
                )
            })?;
            rename_if_exists(
                &pack_root
                    .join("flows")
                    .join(format!("{generic_name}.ygtc.resolve.json")),
                &pack_root
                    .join("flows")
                    .join(format!("{target_flow_id}.ygtc.resolve.json")),
            )?;
            rename_if_exists(
                &pack_root
                    .join("flows")
                    .join(format!("{generic_name}.ygtc.resolve.summary.json")),
                &pack_root
                    .join("flows")
                    .join(format!("{target_flow_id}.ygtc.resolve.summary.json")),
            )?;
            replace_in_file(
                &pack_root.join("pack.yaml"),
                &format!("flows/{generic_name}.ygtc"),
                &format!("flows/{target_flow_id}.ygtc"),
            )?;
            replace_in_file(
                &pack_root.join("extensions/deployer.json"),
                &format!("flows/{generic_name}.ygtc"),
                &format!("flows/{target_flow_id}.ygtc"),
            )?;
        }
    }

    run_command(
        root,
        "greentic-pack",
        &["update", "--in", pack_root.to_str().unwrap()],
    )?;
    Ok(())
}

fn rename_if_exists(src: &Path, dest: &Path) -> Result<()> {
    if src.exists() {
        fs::rename(src, dest)
            .with_context(|| format!("rename {} -> {}", src.display(), dest.display()))?;
    }
    Ok(())
}

fn replace_in_file(path: &Path, from: &str, to: &str) -> Result<()> {
    let content = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let updated = content.replace(from, to);
    fs::write(path, updated).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn load_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

fn run_command(root: &Path, program: &str, args: &[&str]) -> Result<()> {
    let result = run_command_capture(root, program, args)?;
    if result.success {
        return Ok(());
    }
    bail!("{} {} failed:\n{}", program, args.join(" "), result.stderr);
}

fn run_command_in_dir(dir: &Path, program: &str, args: &[&str]) -> Result<()> {
    // Accepted risk: callers pass fixed tool names from this maintenance binary, and no shell is used.
    // foxguard: ignore[rs/no-command-injection]
    let output = Command::new(program)
        .args(args)
        .current_dir(dir)
        .output()
        .with_context(|| format!("run {} {}", program, args.join(" ")))?;
    if output.status.success() {
        return Ok(());
    }
    bail!(
        "{} {} failed in {}:\n{}",
        program,
        args.join(" "),
        dir.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}

struct CommandResult {
    success: bool,
    stderr: String,
}

fn run_command_capture(root: &Path, program: &str, args: &[&str]) -> Result<CommandResult> {
    // Accepted risk: callers pass fixed tool names from this maintenance binary, and no shell is used.
    // foxguard: ignore[rs/no-command-injection]
    let output = Command::new(program)
        .args(args)
        .current_dir(root)
        .output()
        .with_context(|| format!("run {} {}", program, args.join(" ")))?;
    Ok(CommandResult {
        success: output.status.success(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}
