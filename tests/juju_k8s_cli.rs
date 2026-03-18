use std::process::Command;

#[path = "support/provider_pack.rs"]
mod provider_pack;

use provider_pack::{build_provider_gtpack, example_pack_path, write_fake_command_bin};

fn write_test_config(dir: &std::path::Path) -> std::path::PathBuf {
    let state_dir = dir.join("state");
    let cache_dir = dir.join("cache");
    let logs_dir = dir.join("logs");
    let config = format!(
        r#"
[environment]
env_id = "dev"
connection = "offline"

[paths]
greentic_root = "{root}"
state_dir = "{state}"
cache_dir = "{cache}"
logs_dir = "{logs}"

[telemetry]
enabled = false

[network]
tls_mode = "system"

[secrets]
kind = "none"
"#,
        root = dir.display(),
        state = state_dir.display(),
        cache = cache_dir.display(),
        logs = logs_dir.display(),
    );
    let path = dir.join("config.toml");
    std::fs::write(&path, config).expect("write config");
    path
}

#[test]
fn juju_k8s_generate_cli_renders_json_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    let config = write_test_config(dir.path());
    build_provider_gtpack("juju-k8s", &provider_pack, "greentic.deploy.juju-k8s");
    let pack = example_pack_path();

    let output = Command::new(env!("CARGO_BIN_EXE_greentic-deployer"))
        .args([
            "juju-k8s",
            "generate",
            "--tenant",
            "acme",
            "--pack",
            pack.to_str().expect("pack path"),
            "--config",
            config.to_str().expect("config path"),
            "--provider-pack",
            provider_pack.to_str().expect("provider pack"),
            "--output",
            "json",
        ])
        .output()
        .expect("run greentic-deployer");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"strategy\": \"juju-k8s\""));
}

#[test]
fn juju_k8s_status_cli_renders_executed_json_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    let config = write_test_config(dir.path());
    build_provider_gtpack("juju-k8s", &provider_pack, "greentic.deploy.juju-k8s");
    let pack = example_pack_path();

    let output = Command::new(env!("CARGO_BIN_EXE_greentic-deployer"))
        .args([
            "juju-k8s",
            "status",
            "--tenant",
            "acme",
            "--pack",
            pack.to_str().expect("pack path"),
            "--config",
            config.to_str().expect("config path"),
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
    assert!(stdout.contains("\"executed\": true"));
}

#[test]
fn juju_k8s_apply_execute_cli_runs_local_juju_scaffold() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    let config = write_test_config(dir.path());
    build_provider_gtpack("juju-k8s", &provider_pack, "greentic.deploy.juju-k8s");
    let fake_bin_dir = dir.path().join("bin");
    std::fs::create_dir_all(&fake_bin_dir).expect("create fake bin dir");
    write_fake_command_bin(&fake_bin_dir, "juju");
    let pack = example_pack_path();
    let path = std::env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{path}", fake_bin_dir.display());

    let output = Command::new(env!("CARGO_BIN_EXE_greentic-deployer"))
        .env("PATH", combined_path)
        .args([
            "juju-k8s",
            "apply",
            "--tenant",
            "acme",
            "--pack",
            pack.to_str().expect("pack path"),
            "--config",
            config.to_str().expect("config path"),
            "--provider-pack",
            provider_pack.to_str().expect("provider pack"),
            "--execute",
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
    assert!(stdout.contains("\"executed\": true"));
    assert!(stdout.contains("\"strategy\": \"juju-k8s\""));
}
