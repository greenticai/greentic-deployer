use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use greentic_deployer::contract::{
    DeployerContractV1, get_deployer_contract_v1, resolve_deployer_contract_assets,
};
use greentic_deployer::pack_introspect::read_manifest_from_gtpack;

fn main() -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixtures_root = root.join("fixtures/packs");
    let scaffold_root = root.join("target/replayed-pack-scaffolds");
    let output_root = root.join("dist");

    fs::create_dir_all(&output_root).context("create output directory")?;

    let mut fixture_dirs = fs::read_dir(&fixtures_root)
        .with_context(|| format!("read fixture root {}", fixtures_root.display()))?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    fixture_dirs.sort();

    if fixture_dirs.is_empty() {
        bail!("no fixture packs found under {}", fixtures_root.display());
    }

    for fixture_dir in fixture_dirs {
        let fixture_name = fixture_dir
            .file_name()
            .and_then(|name| name.to_str())
            .context("fixture name missing")?;
        let pack_root = scaffold_root.join(fixture_name);
        let output_path = output_root.join(format!("{fixture_name}.gtpack"));
        build_fixture_gtpack(&pack_root, &output_path)?;
        validate_fixture_gtpack(&fixture_dir, &output_path)?;
        let manifest = read_manifest_from_gtpack(&output_path)
            .with_context(|| format!("read manifest from {}", output_path.display()))?;
        println!("built and validated {}", output_path.display());
        let relative_output_path = output_path.strip_prefix(&root).with_context(|| {
            format!("compute relative output path for {}", output_path.display())
        })?;
        println!(
            "PACK\t{}\t{}\t{}",
            manifest.pack_id,
            manifest.version,
            relative_output_path.display()
        );
    }

    Ok(())
}

fn build_fixture_gtpack(pack_root: &Path, output_path: &Path) -> Result<()> {
    ensure!(
        pack_root.join("pack.yaml").is_file(),
        "missing replayed scaffold at {}; run `cargo run --features internal-tools --bin replay_deployer_scaffolds` first",
        pack_root.display()
    );

    run_command(
        "greentic-pack",
        &["build", "--in", pack_root.to_str().unwrap()],
    )?;

    let fixture_name = pack_root
        .file_name()
        .and_then(|name| name.to_str())
        .context("pack root name missing")?;
    let built_path = pack_root
        .join("dist")
        .join(format!("{fixture_name}.gtpack"));
    ensure!(
        built_path.is_file(),
        "greentic-pack did not produce {}",
        built_path.display()
    );
    fs::copy(&built_path, output_path).with_context(|| {
        format!(
            "copy built gtpack {} -> {}",
            built_path.display(),
            output_path.display()
        )
    })?;

    Ok(())
}

fn validate_fixture_gtpack(fixture_dir: &Path, gtpack_path: &Path) -> Result<()> {
    let manifest = read_manifest_from_gtpack(gtpack_path)
        .with_context(|| format!("read manifest from {}", gtpack_path.display()))?;
    let contract = get_deployer_contract_v1(&manifest)
        .context("decode embedded deployer contract")?
        .context("missing embedded deployer contract")?;
    let resolved = resolve_deployer_contract_assets(&manifest, gtpack_path)
        .with_context(|| format!("resolve contract assets from {}", gtpack_path.display()))?;
    let expected = load_contract(fixture_dir)?;

    ensure!(
        contract == expected,
        "embedded contract mismatch for {}",
        fixture_dir.display()
    );
    ensure!(
        resolved
            .as_ref()
            .context("missing resolved deployer contract")?
            .capabilities
            .len()
            == expected.capabilities.len(),
        "resolved capability count mismatch for {}",
        fixture_dir.display()
    );
    ensure!(
        gtpack_path.is_file(),
        "archive missing after build: {}",
        gtpack_path.display()
    );

    Ok(())
}

fn load_contract(fixture_dir: &Path) -> Result<DeployerContractV1> {
    let path = fixture_dir.join("contract.greentic.deployer.v1.json");
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

fn run_command(program: &str, args: &[&str]) -> Result<()> {
    // Accepted risk: callers pass fixed tool names from this maintenance binary, and no shell is used.
    // foxguard: ignore[rs/no-command-injection]
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("run {} {}", program, args.join(" ")))?;
    if output.status.success() {
        return Ok(());
    }
    bail!(
        "{} {} failed:\n{}",
        program,
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
}
