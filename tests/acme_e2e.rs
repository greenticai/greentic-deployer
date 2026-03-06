use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use greentic_deployer::pack_introspect::build_plan;
use greentic_deployer::{
    config::{DeployerConfig, OutputFormat, Provider},
    contract::DeployerCapability,
};
use greentic_types::SemverReq;
use greentic_types::cbor::encode_pack_manifest;
use greentic_types::component::{ComponentCapabilities, ComponentManifest, ComponentProfiles};
use greentic_types::flow::{
    ComponentRef, Flow, FlowHasher, FlowKind, FlowMetadata, InputMapping, Node, OutputMapping,
    Routing,
};
use greentic_types::pack_manifest::{PackDependency, PackKind, PackManifest};
use greentic_types::{ComponentId, FlowId, NodeId, PackId};
use indexmap::IndexMap;
use semver::Version;
use tar::Builder;

fn sample_component(id: &str, http_server: bool) -> ComponentManifest {
    let host_caps = greentic_types::component::HostCapabilities {
        http: Some(greentic_types::component::HttpCapabilities {
            client: true,
            server: http_server,
        }),
        ..Default::default()
    };
    ComponentManifest {
        id: ComponentId::from_str(id).unwrap(),
        version: Version::new(0, 1, 0),
        supports: vec![FlowKind::Messaging, FlowKind::Http],
        world: "greentic:test/world".to_string(),
        profiles: ComponentProfiles {
            default: Some("http_endpoint".to_string()),
            supported: vec![
                "http_endpoint".to_string(),
                "long_lived_service".to_string(),
            ],
        },
        capabilities: ComponentCapabilities {
            host: host_caps,
            ..Default::default()
        },
        configurators: None,
        operations: Vec::new(),
        config_schema: None,
        resources: Default::default(),
        dev_flows: Default::default(),
    }
}

fn sample_flow(id: &str, kind: FlowKind, component: &ComponentManifest) -> Flow {
    let mut nodes: IndexMap<NodeId, Node, FlowHasher> = IndexMap::default();
    nodes.insert(
        NodeId::from_str("start").unwrap(),
        Node {
            id: NodeId::from_str("start").unwrap(),
            component: ComponentRef {
                id: component.id.clone(),
                pack_alias: None,
                operation: None,
            },
            input: InputMapping {
                mapping: serde_json::Value::Null,
            },
            output: OutputMapping {
                mapping: serde_json::Value::Null,
            },
            routing: Routing::End,
            telemetry: Default::default(),
        },
    );

    let mut entrypoints = BTreeMap::new();
    entrypoints.insert("default".to_string(), serde_json::Value::Null);

    Flow {
        schema_version: "flowir-v1".to_string(),
        id: FlowId::from_str(id).unwrap(),
        kind,
        entrypoints,
        nodes,
        metadata: FlowMetadata::default(),
    }
}

fn sample_manifest() -> PackManifest {
    let http_component = sample_component("dev.greentic.http", true);
    let msg_component = sample_component("dev.greentic.msg", false);

    let flows = vec![
        greentic_types::pack_manifest::PackFlowEntry {
            id: FlowId::from_str("chat_flow").unwrap(),
            kind: FlowKind::Messaging,
            flow: sample_flow("chat_flow", FlowKind::Messaging, &msg_component),
            tags: vec!["messaging".to_string()],
            entrypoints: vec!["default".to_string()],
        },
        greentic_types::pack_manifest::PackFlowEntry {
            id: FlowId::from_str("http_flow").unwrap(),
            kind: FlowKind::Http,
            flow: sample_flow("http_flow", FlowKind::Http, &http_component),
            tags: vec!["http".to_string()],
            entrypoints: vec!["default".to_string()],
        },
    ];

    PackManifest {
        schema_version: "pack-v1".to_string(),
        pack_id: PackId::from_str("dev.greentic.sample").unwrap(),
        name: None,
        version: Version::new(0, 1, 0),
        kind: PackKind::Application,
        publisher: "greentic".to_string(),
        secret_requirements: Vec::new(),
        components: vec![http_component, msg_component],
        flows,
        dependencies: vec![PackDependency {
            alias: "common".to_string(),
            pack_id: PackId::from_str("dev.greentic.common").unwrap(),
            version_req: SemverReq::parse("*").unwrap(),
            required_capabilities: vec![],
        }],
        capabilities: Vec::new(),
        signatures: Default::default(),
        bootstrap: None,
        extensions: None,
    }
}

fn write_gtpack_tar(manifest: &PackManifest, path: &Path) {
    let encoded = encode_pack_manifest(manifest).expect("encode manifest");
    let mut builder = Builder::new(Vec::new());

    let mut manifest_header = tar::Header::new_gnu();
    manifest_header.set_size(encoded.len() as u64);
    manifest_header.set_mode(0o644);
    manifest_header.set_cksum();
    builder
        .append_data(&mut manifest_header, "manifest.cbor", encoded.as_slice())
        .expect("append manifest");

    let dummy = b"wasm";
    let mut comp_header = tar::Header::new_gnu();
    comp_header.set_size(dummy.len() as u64);
    comp_header.set_mode(0o644);
    comp_header.set_cksum();
    builder
        .append_data(
            &mut comp_header,
            "components/dev.greentic.http.wasm",
            dummy.as_slice(),
        )
        .expect("append component");

    let bytes = builder.into_inner().expect("tar bytes");
    let mut file = fs::File::create(path).expect("create tar");
    file.write_all(&bytes).expect("write tar");
}

fn write_directory_pack(manifest: &PackManifest, root: &Path) {
    let encoded = encode_pack_manifest(manifest).expect("encode manifest");
    fs::create_dir_all(root.join("components")).expect("mkdir components");
    fs::write(root.join("manifest.cbor"), encoded).expect("write manifest");
    fs::write(root.join("components/dev.greentic.http.wasm"), b"wasm").expect("write component");
}

fn default_config(pack_path: PathBuf) -> DeployerConfig {
    DeployerConfig {
        capability: DeployerCapability::Plan,
        provider: Provider::Aws,
        strategy: "iac-only".into(),
        tenant: "acme".into(),
        environment: "dev".into(),
        pack_path,
        providers_dir: PathBuf::from("providers/deployer"),
        packs_dir: PathBuf::from("packs"),
        provider_pack: None,
        pack_ref: None,
        distributor_url: None,
        distributor_token: None,
        preview: false,
        dry_run: false,
        output: OutputFormat::Text,
        greentic: greentic_config::ConfigResolver::new()
            .load()
            .expect("load default config")
            .config,
        provenance: greentic_config::ProvenanceMap::new(),
        config_warnings: Vec::new(),
    }
}

#[test]
fn builds_plan_from_tar_gtpack() {
    let manifest = sample_manifest();
    let base = std::env::current_dir()
        .expect("cwd")
        .join("target/tmp-tests");
    std::fs::create_dir_all(&base).expect("create tmp base");
    let dir = tempfile::tempdir_in(base).expect("temp dir");
    let tar_path = dir.path().join("sample.gtpack");
    write_gtpack_tar(&manifest, &tar_path);

    let config = default_config(tar_path);
    let plan = build_plan(&config).expect("plan builds");
    assert_eq!(plan.plan.pack_id, manifest.pack_id.to_string());
    assert!(!plan.plan.channels.is_empty());
    assert!(!plan.components.is_empty());
}

#[test]
fn builds_plan_from_directory_pack() {
    let manifest = sample_manifest();
    let base = std::env::current_dir()
        .expect("cwd")
        .join("target/tmp-tests");
    std::fs::create_dir_all(&base).expect("create tmp base");
    let dir = tempfile::tempdir_in(base).expect("temp dir");
    write_directory_pack(&manifest, dir.path());

    let config = default_config(dir.path().to_path_buf());
    let plan = build_plan(&config).expect("plan builds");
    assert_eq!(plan.plan.pack_version, manifest.version);
    assert_eq!(plan.target, greentic_deployer::plan::Target::Aws);
    assert_eq!(plan.plan.tenant, "acme");
}
