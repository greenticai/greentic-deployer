use std::process::Command;

#[path = "support/cli_binary.rs"]
mod cli_binary;
#[path = "support/provider_pack.rs"]
mod provider_pack;

use cli_binary::{command_output_with_busy_retry, copied_test_binary};
use provider_pack::{build_provider_gtpack, example_pack_path, write_fake_terraform_bin};

#[test]
fn azure_generate_cli_renders_json_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    build_provider_gtpack("terraform", &provider_pack, "greentic.deploy.azure");
    let pack = example_pack_path();
    let binary = copied_test_binary(&dir);

    let output = command_output_with_busy_retry(Command::new(&binary).args([
        "azure",
        "generate",
        "--tenant",
        "acme",
        "--pack",
        pack.to_str().expect("pack path"),
        "--provider-pack",
        provider_pack.to_str().expect("provider pack"),
        "--output",
        "json",
    ]));

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"capability\": \"generate\""));
    assert!(stdout.contains("\"provider\": \"azure\""));
    assert!(stdout.contains("\"strategy\": \"iac-only\""));
}

#[test]
fn azure_status_cli_renders_json_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    build_provider_gtpack("terraform", &provider_pack, "greentic.deploy.azure");
    let pack = example_pack_path();
    let binary = copied_test_binary(&dir);

    let output = command_output_with_busy_retry(Command::new(&binary).args([
        "azure",
        "status",
        "--tenant",
        "acme",
        "--pack",
        pack.to_str().expect("pack path"),
        "--provider-pack",
        provider_pack.to_str().expect("provider pack"),
        "--output",
        "json",
    ]));

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"capability\": \"status\""));
    assert!(stdout.contains("\"provider\": \"azure\""));
    assert!(stdout.contains("\"strategy\": \"iac-only\""));
    assert!(stdout.contains("\"flow_id\": \"status_terraform\""));
}

#[test]
fn azure_apply_execute_cli_runs_local_terraform_scaffold() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    build_provider_gtpack("terraform", &provider_pack, "greentic.deploy.azure");
    let fake_bin_dir = dir.path().join("bin");
    std::fs::create_dir_all(&fake_bin_dir).expect("create fake bin dir");
    write_fake_terraform_bin(&fake_bin_dir);
    let pack = example_pack_path();
    let binary = copied_test_binary(&dir);
    let path = std::env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{path}", fake_bin_dir.display());

    let output =
        command_output_with_busy_retry(Command::new(&binary).env("PATH", combined_path).args([
            "azure",
            "apply",
            "--tenant",
            "acme",
            "--pack",
            pack.to_str().expect("pack path"),
            "--provider-pack",
            provider_pack.to_str().expect("provider pack"),
            "--execute",
            "--output",
            "json",
        ]));

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"capability\": \"apply\""));
    assert!(stdout.contains("\"executed\": true"));
    assert!(stdout.contains("\"provider\": \"azure\""));
}
