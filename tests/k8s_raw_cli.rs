use std::process::Command;

#[path = "support/cli_binary.rs"]
mod cli_binary;
#[path = "support/provider_pack.rs"]
mod provider_pack;

use cli_binary::{command_output_with_busy_retry, copied_test_binary};
use provider_pack::{build_provider_gtpack, example_pack_path};

#[test]
fn k8s_raw_generate_cli_renders_json_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    build_provider_gtpack("k8s-raw", &provider_pack, "greentic.deploy.k8s");
    let pack = example_pack_path();
    let binary = copied_test_binary(&dir);

    let output = command_output_with_busy_retry(Command::new(&binary).args([
        "k8s-raw",
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
    assert!(stdout.contains("\"provider\": \"k8s\""));
    assert!(stdout.contains("\"strategy\": \"raw-manifests\""));
}

#[test]
fn k8s_raw_status_cli_renders_json_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    build_provider_gtpack("k8s-raw", &provider_pack, "greentic.deploy.k8s");
    let pack = example_pack_path();
    let binary = copied_test_binary(&dir);

    let output = command_output_with_busy_retry(Command::new(&binary).args([
        "k8s-raw",
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
    assert!(stdout.contains("\"provider\": \"k8s\""));
    assert!(stdout.contains("\"strategy\": \"raw-manifests\""));
    assert!(stdout.contains("\"flow_id\": \"status_k8s_raw\""));
}
