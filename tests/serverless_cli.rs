use std::process::Command;

#[path = "support/cli_binary.rs"]
mod cli_binary;
#[path = "support/provider_pack.rs"]
mod provider_pack;

use cli_binary::{command_output_with_busy_retry, copied_test_binary};
use provider_pack::{build_provider_gtpack, example_pack_path};

#[test]
fn serverless_generate_cli_renders_json_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    build_provider_gtpack("serverless", &provider_pack, "greentic.deploy.serverless");
    let pack = example_pack_path();
    let binary = copied_test_binary(&dir);

    let output = command_output_with_busy_retry(Command::new(&binary).args([
        "serverless",
        "generate",
        "--tenant",
        "acme-serverless-generate",
        "--pack",
        pack.to_str().expect("pack path"),
        "--provider-pack",
        provider_pack.to_str().expect("provider pack"),
        "--output",
        "json",
    ]));

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"capability\": \"generate\""));
    assert!(stdout.contains("\"provider\": \"generic\""));
    assert!(stdout.contains("\"strategy\": \"serverless-container\""));
}

#[test]
fn serverless_apply_preview_cli_renders_json_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    build_provider_gtpack("serverless", &provider_pack, "greentic.deploy.serverless");
    let pack = example_pack_path();
    let binary = copied_test_binary(&dir);

    let output = command_output_with_busy_retry(Command::new(&binary).args([
        "serverless",
        "apply",
        "--tenant",
        "acme-serverless-apply-preview",
        "--pack",
        pack.to_str().expect("pack path"),
        "--provider-pack",
        provider_pack.to_str().expect("provider pack"),
        "--preview",
        "--output",
        "json",
    ]));

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"capability\": \"apply\""));
    assert!(stdout.contains("\"provider\": \"generic\""));
    assert!(stdout.contains("\"strategy\": \"serverless-container\""));
}

#[test]
fn serverless_status_cli_renders_executed_json_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    build_provider_gtpack("serverless", &provider_pack, "greentic.deploy.serverless");
    let pack = example_pack_path();
    let binary = copied_test_binary(&dir);

    let output = command_output_with_busy_retry(Command::new(&binary).args([
        "serverless",
        "status",
        "--tenant",
        "acme-serverless-status",
        "--pack",
        pack.to_str().expect("pack path"),
        "--provider-pack",
        provider_pack.to_str().expect("provider pack"),
        "--output",
        "json",
    ]));

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"capability\": \"status\""));
    assert!(stdout.contains("\"executed\": true"));
    assert!(stdout.contains("\"strategy\": \"serverless-container\""));
}

#[test]
fn serverless_apply_execute_cli_runs_local_scaffold() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    build_provider_gtpack("serverless", &provider_pack, "greentic.deploy.serverless");
    let pack = example_pack_path();
    let binary = copied_test_binary(&dir);

    let output = command_output_with_busy_retry(Command::new(&binary).args([
        "serverless",
        "apply",
        "--tenant",
        "acme-serverless-apply-execute",
        "--pack",
        pack.to_str().expect("pack path"),
        "--provider-pack",
        provider_pack.to_str().expect("provider pack"),
        "--execute",
        "--output",
        "json",
    ]));

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"capability\": \"apply\""));
    assert!(stdout.contains("\"executed\": true"));
    assert!(stdout.contains("\"strategy\": \"serverless-container\""));
}
