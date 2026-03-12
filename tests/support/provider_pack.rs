use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use greentic_deployer::contract::{DeployerContractV1, set_deployer_contract_v1};
use greentic_types::flow::{Flow, FlowHasher, FlowKind, FlowMetadata};
use greentic_types::pack_manifest::{PackFlowEntry, PackKind, PackManifest};
use greentic_types::{FlowId, PackId};
use indexmap::IndexMap;
use semver::Version;
use tar::Builder;

pub fn example_pack_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join("acme-pack")
}

fn fixture_root(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("packs")
        .join(name)
}

pub fn build_provider_gtpack(fixture_name: &str, output_path: &Path, pack_id: &str) {
    let fixture_dir = fixture_root(fixture_name);
    let contract_path = fixture_dir.join("contract.greentic.deployer.v1.json");
    let contract: DeployerContractV1 =
        serde_json::from_slice(&fs::read(&contract_path).expect("read contract"))
            .expect("parse contract");

    let mut manifest = PackManifest {
        schema_version: "pack-v1".to_string(),
        pack_id: PackId::from_str(pack_id).expect("pack id"),
        name: Some("Fixture terraform provider pack".to_string()),
        version: Version::new(0, 4, 17),
        kind: PackKind::Application,
        publisher: "greentic".to_string(),
        secret_requirements: Vec::new(),
        components: Vec::new(),
        flows: contract_flow_entries(&contract),
        dependencies: Vec::new(),
        capabilities: Vec::new(),
        signatures: Default::default(),
        bootstrap: None,
        extensions: None,
    };
    set_deployer_contract_v1(&mut manifest, contract).expect("embed contract");
    let encoded = greentic_types::cbor::encode_pack_manifest(&manifest).expect("encode manifest");

    let file = File::create(output_path).expect("create output archive");
    let mut builder = Builder::new(file);
    append_bytes(&mut builder, Path::new("manifest.cbor"), &encoded);
    append_fixture_tree(&mut builder, &fixture_dir, &fixture_dir);
    builder.finish().expect("finish archive");
}

fn contract_flow_entries(contract: &DeployerContractV1) -> Vec<PackFlowEntry> {
    let mut ids = std::collections::BTreeSet::new();
    ids.insert(contract.planner.flow_id.clone());
    for capability in &contract.capabilities {
        ids.insert(capability.flow_id.clone());
    }

    ids.into_iter()
        .map(|id| {
            let flow_id = FlowId::from_str(&id).expect("flow id");
            PackFlowEntry {
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
            }
        })
        .collect()
}

fn append_fixture_tree(builder: &mut Builder<File>, root: &Path, current: &Path) {
    let mut entries = fs::read_dir(current)
        .expect("read fixture dir")
        .flatten()
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    entries.sort();

    for path in entries {
        if path.is_dir() {
            append_fixture_tree(builder, root, &path);
        } else if path.is_file() {
            let relative = path.strip_prefix(root).expect("relative path");
            let bytes = fs::read(&path).expect("read fixture file");
            append_bytes(builder, relative, &bytes);
        }
    }
}

fn append_bytes(builder: &mut Builder<File>, path: &Path, bytes: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, path, bytes)
        .expect("append bytes");
}

#[allow(dead_code)]
pub fn write_fake_terraform_bin(dir: &Path) -> PathBuf {
    write_fake_command_bin(dir, "terraform")
}

#[allow(dead_code)]
pub fn write_fake_command_bin(dir: &Path, command_name: &str) -> PathBuf {
    let path = dir.join(command_name);
    fs::write(
        &path,
        format!(
            "#!/usr/bin/env bash\nset -euo pipefail\necho \"fake {} $*\"\n",
            command_name
        ),
    )
    .expect("write fake command");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).expect("set permissions");
    }
    path
}
