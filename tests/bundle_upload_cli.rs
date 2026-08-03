//! End-to-end CLI smoke tests for `greentic-deployer bundle-upload …`.
//!
//! Verifies the JSON error envelope on stderr matches the shape `op` emits
//! (`{"op": ..., "noun": ..., "error": {"kind": ..., "message": ...}}`) and
//! that it never leaks onto stdout, which callers reserve for the success
//! payload.

use std::process::Command;

#[path = "support/cli_binary.rs"]
mod cli_binary;

use cli_binary::{command_output_with_busy_retry, copied_test_binary};

#[test]
fn bundle_upload_unsupported_scheme_emits_json_error_envelope() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bundle_path = dir.path().join("bundle.gtbundle");
    let binary = copied_test_binary(&dir);

    let output = command_output_with_busy_retry(Command::new(&binary).args([
        "bundle-upload",
        "upload",
        "--target",
        "ftp://nope",
        "--bundle",
        bundle_path.to_str().expect("bundle path"),
    ]));

    assert!(
        !output.status.success(),
        "expected non-zero exit for unsupported scheme; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let envelope: serde_json::Value = serde_json::from_str(stderr.trim())
        .unwrap_or_else(|err| panic!("stderr is not JSON (err={err}): {stderr}"));

    assert_eq!(envelope["op"], "upload");
    assert_eq!(envelope["noun"], "bundle-upload");
    assert_eq!(envelope["error"]["kind"], "bundle_upload.invalid_url");
    assert!(
        envelope["error"]["message"]
            .as_str()
            .is_some_and(|m| !m.is_empty()),
        "error.message should be non-empty: {}",
        envelope["error"]
    );

    assert!(
        output.stdout.is_empty(),
        "stdout must stay clean on the error path (it carries the success payload): {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn bundle_upload_refresh_url_unsupported_scheme_emits_json_error_envelope() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = copied_test_binary(&dir);

    let output = command_output_with_busy_retry(Command::new(&binary).args([
        "bundle-upload",
        "refresh-url",
        "--object-ref",
        "ftp://nope",
    ]));

    assert!(
        !output.status.success(),
        "expected non-zero exit for unsupported scheme; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let envelope: serde_json::Value = serde_json::from_str(stderr.trim())
        .unwrap_or_else(|err| panic!("stderr is not JSON (err={err}): {stderr}"));

    assert_eq!(envelope["op"], "refresh-url");
    assert_eq!(envelope["noun"], "bundle-upload");
    assert_eq!(envelope["error"]["kind"], "bundle_upload.invalid_url");
    assert!(
        envelope["error"]["message"]
            .as_str()
            .is_some_and(|m| !m.is_empty()),
        "error.message should be non-empty: {}",
        envelope["error"]
    );

    assert!(
        output.stdout.is_empty(),
        "stdout must stay clean on the error path (it carries the success payload): {}",
        String::from_utf8_lossy(&output.stdout)
    );
}
