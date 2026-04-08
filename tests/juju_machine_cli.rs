use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

#[path = "support/provider_pack.rs"]
mod provider_pack;

use provider_pack::{build_provider_gtpack, example_pack_path, write_fake_command_bin};

fn copied_test_binary(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let source = std::path::Path::new(env!("CARGO_BIN_EXE_greentic-deployer"));
    let target = dir.path().join("greentic-deployer");
    std::fs::copy(source, &target).expect("copy greentic-deployer test binary");
    target
}

fn cli_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn command_output_with_busy_retry(command: &mut Command) -> std::process::Output {
    let _guard = cli_test_lock().lock().expect("lock cli test process execution");
    let mut attempts = 0;
    loop {
        match command.output() {
            Ok(output) => return output,
            Err(err) if err.kind() == std::io::ErrorKind::ExecutableFileBusy && attempts < 5 => {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(err) => panic!("run greentic-deployer: {err}"),
        }
    }
}

#[test]
fn juju_machine_generate_cli_renders_json_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    build_provider_gtpack(
        "juju-machine",
        &provider_pack,
        "greentic.deploy.juju-machine",
    );
    let pack = example_pack_path();
    let binary = copied_test_binary(&dir);

    let output = command_output_with_busy_retry(Command::new(&binary).args([
        "juju-machine",
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
    assert!(stdout.contains("\"strategy\": \"juju-machine\""));
}

#[test]
fn juju_machine_status_cli_renders_executed_json_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    build_provider_gtpack(
        "juju-machine",
        &provider_pack,
        "greentic.deploy.juju-machine",
    );
    let pack = example_pack_path();
    let binary = copied_test_binary(&dir);

    let output = command_output_with_busy_retry(Command::new(&binary).args([
        "juju-machine",
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
    assert!(stdout.contains("\"executed\": true"));
}

#[test]
fn juju_machine_apply_execute_cli_runs_local_juju_scaffold() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider_pack = dir.path().join("provider.gtpack");
    build_provider_gtpack(
        "juju-machine",
        &provider_pack,
        "greentic.deploy.juju-machine",
    );
    let fake_bin_dir = dir.path().join("bin");
    std::fs::create_dir_all(&fake_bin_dir).expect("create fake bin dir");
    write_fake_command_bin(&fake_bin_dir, "juju");
    let pack = example_pack_path();
    let binary = copied_test_binary(&dir);
    let path = std::env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{path}", fake_bin_dir.display());

    let output =
        command_output_with_busy_retry(Command::new(&binary).env("PATH", combined_path).args([
            "juju-machine",
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
    assert!(stdout.contains("\"strategy\": \"juju-machine\""));
}
