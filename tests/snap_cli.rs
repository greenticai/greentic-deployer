use std::process::Command;

#[path = "support/provider_pack.rs"]
mod provider_pack;

use provider_pack::{build_provider_gtpack, example_pack_path};

#[test]
fn snap_generate_cli_renders_json_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    build_provider_gtpack("snap", &provider_pack, "greentic.deploy.snap");
    let pack = example_pack_path();

    let output = Command::new(env!("CARGO_BIN_EXE_greentic-deployer"))
        .args([
            "snap",
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

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"provider\": \"local\""));
    assert!(stdout.contains("\"strategy\": \"snap\""));
}

#[test]
fn snap_status_cli_renders_executed_json_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    build_provider_gtpack("snap", &provider_pack, "greentic.deploy.snap");
    let pack = example_pack_path();

    let output = Command::new(env!("CARGO_BIN_EXE_greentic-deployer"))
        .args([
            "snap",
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

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"capability\": \"status\""));
    assert!(stdout.contains("\"executed\": true"));
}
