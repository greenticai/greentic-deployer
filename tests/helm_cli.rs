use std::process::Command;

#[path = "support/provider_pack.rs"]
mod provider_pack;

use provider_pack::{build_provider_gtpack, example_pack_path};

#[test]
fn helm_generate_cli_renders_json_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    build_provider_gtpack("helm", &provider_pack, "greentic.deploy.helm");
    let pack = example_pack_path();

    let output = Command::new(env!("CARGO_BIN_EXE_greentic-deployer"))
        .args([
            "helm",
            "generate",
            "--tenant",
            "acme",
            "--pack",
            pack.to_str().expect("pack path"),
            "--provider-pack",
            provider_pack.to_str().expect("provider pack"),
            "--output",
            "json",
        ])
        .output()
        .expect("run greentic-deployer");

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"capability\": \"generate\""));
    assert!(stdout.contains("\"provider\": \"k8s\""));
    assert!(stdout.contains("\"strategy\": \"helm\""));
}

#[test]
fn helm_status_cli_renders_json_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    build_provider_gtpack("helm", &provider_pack, "greentic.deploy.helm");
    let pack = example_pack_path();

    let output = Command::new(env!("CARGO_BIN_EXE_greentic-deployer"))
        .args([
            "helm",
            "status",
            "--tenant",
            "acme",
            "--pack",
            pack.to_str().expect("pack path"),
            "--provider-pack",
            provider_pack.to_str().expect("provider pack"),
            "--output",
            "json",
        ])
        .output()
        .expect("run greentic-deployer");

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"capability\": \"status\""));
    assert!(stdout.contains("\"provider\": \"k8s\""));
    assert!(stdout.contains("\"strategy\": \"helm\""));
    assert!(stdout.contains("\"flow_id\": \"status_helm\""));
}
