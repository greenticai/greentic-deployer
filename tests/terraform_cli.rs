use std::process::Command;

#[path = "support/provider_pack.rs"]
mod provider_pack;

use provider_pack::{build_provider_gtpack, example_pack_path};

#[test]
fn terraform_generate_cli_renders_json_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    build_provider_gtpack("terraform", &provider_pack, "greentic.deploy.terraform");
    let pack = example_pack_path();

    let output = Command::new(env!("CARGO_BIN_EXE_greentic-deployer"))
        .args([
            "terraform",
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
    assert!(stdout.contains("\"provider\": \"generic\""));
    assert!(stdout.contains("\"strategy\": \"terraform\""));
}

#[test]
fn terraform_plan_cli_renders_text_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    build_provider_gtpack("terraform", &provider_pack, "greentic.deploy.terraform");
    let pack = example_pack_path();

    let output = Command::new(env!("CARGO_BIN_EXE_greentic-deployer"))
        .args([
            "terraform",
            "plan",
            "--tenant",
            "acme",
            "--pack",
            pack.to_str().expect("pack path"),
            "--provider-pack",
            provider_pack.to_str().expect("provider pack"),
            "--output",
            "text",
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
    assert!(stdout.contains("capability=plan"));
    assert!(stdout.contains("pack_id=greentic.deploy.terraform"));
    assert!(stdout.contains("payload_kind=plan"));
}

#[test]
fn terraform_plan_cli_renders_json_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    build_provider_gtpack("terraform", &provider_pack, "greentic.deploy.terraform");
    let pack = example_pack_path();

    let output = Command::new(env!("CARGO_BIN_EXE_greentic-deployer"))
        .args([
            "terraform",
            "plan",
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
    assert!(stdout.contains("\"capability\": \"plan\""));
    assert!(stdout.contains("\"provider\": \"generic\""));
    assert!(stdout.contains("\"strategy\": \"terraform\""));
    assert!(stdout.contains("\"flow_id\": \"plan_terraform\""));
}

#[test]
fn terraform_apply_preview_cli_renders_json_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    build_provider_gtpack("terraform", &provider_pack, "greentic.deploy.terraform");
    let pack = example_pack_path();

    let output = Command::new(env!("CARGO_BIN_EXE_greentic-deployer"))
        .args([
            "terraform",
            "apply",
            "--tenant",
            "acme",
            "--pack",
            pack.to_str().expect("pack path"),
            "--provider-pack",
            provider_pack.to_str().expect("provider pack"),
            "--preview",
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
    assert!(stdout.contains("\"capability\": \"apply\""));
    assert!(stdout.contains("\"preview\": true"));
    assert!(stdout.contains("\"flow_id\": \"apply_terraform\""));
}

#[test]
fn terraform_destroy_preview_cli_renders_json_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    build_provider_gtpack("terraform", &provider_pack, "greentic.deploy.terraform");
    let pack = example_pack_path();

    let output = Command::new(env!("CARGO_BIN_EXE_greentic-deployer"))
        .args([
            "terraform",
            "destroy",
            "--tenant",
            "acme",
            "--pack",
            pack.to_str().expect("pack path"),
            "--provider-pack",
            provider_pack.to_str().expect("provider pack"),
            "--preview",
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
    assert!(stdout.contains("\"capability\": \"destroy\""));
    assert!(stdout.contains("\"preview\": true"));
    assert!(stdout.contains("\"flow_id\": \"destroy_terraform\""));
}

#[test]
fn terraform_status_cli_renders_json_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    build_provider_gtpack("terraform", &provider_pack, "greentic.deploy.terraform");
    let pack = example_pack_path();

    let output = Command::new(env!("CARGO_BIN_EXE_greentic-deployer"))
        .args([
            "terraform",
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
    assert!(stdout.contains("\"provider\": \"generic\""));
    assert!(stdout.contains("\"strategy\": \"terraform\""));
    assert!(stdout.contains("\"flow_id\": \"status_terraform\""));
}

#[test]
fn terraform_rollback_preview_cli_renders_json_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    build_provider_gtpack("terraform", &provider_pack, "greentic.deploy.terraform");
    let pack = example_pack_path();

    let output = Command::new(env!("CARGO_BIN_EXE_greentic-deployer"))
        .args([
            "terraform",
            "rollback",
            "--tenant",
            "acme",
            "--pack",
            pack.to_str().expect("pack path"),
            "--provider-pack",
            provider_pack.to_str().expect("provider pack"),
            "--preview",
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
    assert!(stdout.contains("\"capability\": \"rollback\""));
    assert!(stdout.contains("\"preview\": true"));
    assert!(stdout.contains("\"flow_id\": \"rollback_terraform\""));
    assert!(stdout.contains("\"target_capability\": \"apply\""));
}
