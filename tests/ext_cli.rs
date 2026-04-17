#![cfg(feature = "extensions")]

use std::path::PathBuf;
use std::process::Command;

#[path = "support/cli_binary.rs"]
mod cli_binary;

use cli_binary::{command_output_with_busy_retry, copied_test_binary};

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/ext")
}

#[test]
fn ext_list_lists_fixture_target() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = copied_test_binary(&dir);
    let output = command_output_with_busy_retry(Command::new(&binary).args([
        "ext",
        "--ext-dir",
        fixture_dir().to_str().expect("utf8 fixture dir"),
        "list",
    ]));
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("testfixture-noop"));
    assert!(stdout.contains("greentic.deploy-testfixture"));
    assert!(stdout.contains("builtin:terraform"));
}

#[test]
fn ext_info_prints_metadata() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = copied_test_binary(&dir);
    let output = command_output_with_busy_retry(Command::new(&binary).args([
        "ext",
        "--ext-dir",
        fixture_dir().to_str().expect("utf8 fixture dir"),
        "info",
        "greentic.deploy-testfixture",
    ]));
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("id:      greentic.deploy-testfixture"));
    assert!(stdout.contains("version: 0.1.0"));
    assert!(stdout.contains("- testfixture-noop"));
}

#[test]
fn ext_validate_exits_zero_for_valid_fixture_dir() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = copied_test_binary(&dir);
    let output = command_output_with_busy_retry(Command::new(&binary).args([
        "ext",
        "validate",
        fixture_dir().to_str().expect("utf8 fixture dir"),
    ]));
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("OK  greentic.deploy-testfixture"));
}
