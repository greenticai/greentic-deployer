use std::collections::BTreeSet;
use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result, bail, ensure};
use greentic_deployer::contract::{
    DeployerContractV1, get_deployer_contract_v1, resolve_deployer_contract_assets,
    set_deployer_contract_v1,
};
use greentic_deployer::pack_introspect::read_manifest_from_gtpack;
use greentic_types::flow::{Flow, FlowHasher, FlowKind, FlowMetadata};
use greentic_types::pack_manifest::{PackFlowEntry, PackKind, PackManifest};
use greentic_types::{FlowId, PackId};
use indexmap::IndexMap;
use semver::Version;
use tar::Builder;

fn main() -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixtures_root = root.join("fixtures/packs");
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
        let output_path = output_root.join(format!("{fixture_name}.gtpack"));
        let manifest = build_fixture_gtpack(&fixture_dir, &output_path)?;
        validate_fixture_gtpack(&fixture_dir, &output_path)?;
        println!("built and validated {}", output_path.display());
        let relative_output_path = output_path
            .strip_prefix(&root)
            .with_context(|| format!("compute relative output path for {}", output_path.display()))?;
        println!(
            "PACK\t{}\t{}\t{}",
            manifest.pack_id,
            manifest.version,
            relative_output_path.display()
        );
    }

    Ok(())
}

fn build_fixture_gtpack(fixture_dir: &Path, output_path: &Path) -> Result<PackManifest> {
    let contract = load_contract(fixture_dir)?;
    let manifest = build_manifest(fixture_dir, &contract)?;
    let encoded =
        greentic_types::cbor::encode_pack_manifest(&manifest).context("encode manifest")?;

    let file = File::create(output_path)
        .with_context(|| format!("create output archive {}", output_path.display()))?;
    let mut builder = Builder::new(file);

    append_bytes(&mut builder, Path::new("manifest.cbor"), &encoded)?;
    append_fixture_tree(&mut builder, fixture_dir, fixture_dir)?;
    builder.finish().context("finish gtpack archive")?;

    Ok(manifest)
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

fn build_manifest(fixture_dir: &Path, contract: &DeployerContractV1) -> Result<PackManifest> {
    let fixture_name = fixture_dir
        .file_name()
        .and_then(|name| name.to_str())
        .context("fixture name missing")?;
    let pack_id = fixture_name.replace('-', ".");
    let package_version =
        Version::parse(env!("CARGO_PKG_VERSION")).context("parse package version")?;
    let mut manifest = PackManifest {
        schema_version: "pack-v1".to_string(),
        pack_id: PackId::from_str(&format!("greentic.fixture.{pack_id}"))
            .context("build pack id")?,
        name: Some(format!("Fixture {}", fixture_name)),
        version: package_version,
        kind: PackKind::Application,
        publisher: "greentic".to_string(),
        secret_requirements: Vec::new(),
        components: Vec::new(),
        flows: contract_flow_entries(contract)?,
        dependencies: Vec::new(),
        capabilities: Vec::new(),
        signatures: Default::default(),
        bootstrap: None,
        extensions: None,
    };
    set_deployer_contract_v1(&mut manifest, contract.clone()).context("embed deployer contract")?;
    Ok(manifest)
}

fn contract_flow_entries(contract: &DeployerContractV1) -> Result<Vec<PackFlowEntry>> {
    let mut ids = BTreeSet::new();
    ids.insert(contract.planner.flow_id.clone());
    for capability in &contract.capabilities {
        ids.insert(capability.flow_id.clone());
    }

    ids.into_iter()
        .map(|id| {
            let flow_id = FlowId::from_str(&id)
                .with_context(|| format!("invalid flow id in contract: {id}"))?;
            Ok(PackFlowEntry {
                id: flow_id.clone(),
                kind: FlowKind::Messaging,
                flow: Flow {
                    schema_version: "flowir-v1".to_string(),
                    id: flow_id,
                    kind: FlowKind::Messaging,
                    entrypoints: Default::default(),
                    nodes: IndexMap::<_, _, FlowHasher>::default(),
                    metadata: FlowMetadata::default(),
                },
                tags: Vec::new(),
                entrypoints: Vec::new(),
            })
        })
        .collect()
}

fn append_fixture_tree(builder: &mut Builder<File>, root: &Path, current: &Path) -> Result<()> {
    let mut entries = fs::read_dir(current)
        .with_context(|| format!("read directory {}", current.display()))?
        .flatten()
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    entries.sort();

    for path in entries {
        if path.is_dir() {
            append_fixture_tree(builder, root, &path)?;
        } else if path.is_file() {
            let relative = path
                .strip_prefix(root)
                .with_context(|| format!("compute relative path for {}", path.display()))?;
            let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            append_bytes(builder, relative, &bytes)?;
        }
    }

    Ok(())
}

fn append_bytes(builder: &mut Builder<File>, path: &Path, bytes: &[u8]) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, path, bytes)
        .with_context(|| format!("append {}", path.display()))?;
    Ok(())
}
