#![cfg(feature = "extensions")]

#[path = "support/env_guard.rs"]
mod env_guard;

use env_guard::EnvGuard;
use greentic_deployer::ext::cli::{
    ExtApplyArgs, ExtDestroyArgs, run_apply, run_apply_with_invoker, run_destroy_with_invoker,
};
use greentic_deployer::ext::errors::ExtensionError;
use greentic_deployer::ext::loader::scan;
use greentic_deployer::ext::registry::ExtensionRegistry;
use greentic_deployer::ext::wasm::MockInvoker;
use std::path::PathBuf;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/ext")
}

fn write_tempfile(dir: &std::path::Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    path
}

fn build_fixture_registry() -> ExtensionRegistry {
    let loaded = scan(&fixture_dir()).expect("scan fixture dir");
    ExtensionRegistry::build(loaded)
}

#[test]
fn ext_apply_missing_target_returns_target_not_found() {
    let _env = EnvGuard::set("GREENTIC_EXT_ALLOW_UNSIGNED", "1");
    let tmp = tempfile::tempdir().unwrap();
    let creds = write_tempfile(tmp.path(), "creds.json", "{}");
    let config = write_tempfile(tmp.path(), "config.json", "{}");
    let reg = build_fixture_registry();
    let invoker = MockInvoker::default();
    let args = ExtApplyArgs {
        target: "does-not-exist".into(),
        creds,
        config,
        pack: None,
        strict_validate: false,
    };
    let err = run_apply_with_invoker(args, &reg, &invoker).unwrap_err();
    assert!(
        matches!(err, ExtensionError::TargetNotFound(_)),
        "got: {err:?}"
    );
}

#[test]
fn ext_destroy_missing_target_returns_target_not_found() {
    let _env = EnvGuard::set("GREENTIC_EXT_ALLOW_UNSIGNED", "1");
    let tmp = tempfile::tempdir().unwrap();
    let creds = write_tempfile(tmp.path(), "creds.json", "{}");
    let config = write_tempfile(tmp.path(), "config.json", "{}");
    let reg = build_fixture_registry();
    let invoker = MockInvoker::default();
    let args = ExtDestroyArgs {
        target: "does-not-exist".into(),
        creds,
        config,
        pack: None,
        strict_validate: false,
    };
    let err = run_destroy_with_invoker(args, &reg, &invoker).unwrap_err();
    assert!(
        matches!(err, ExtensionError::TargetNotFound(_)),
        "got: {err:?}"
    );
}

#[test]
fn ext_apply_testfixture_terraform_returns_adapter_not_implemented() {
    // The existing fixture uses backend=terraform, which is NOT in the
    // Phase B #4a adapter table. A successful dispatch must therefore bubble
    // AdapterNotImplemented rather than silently succeed.
    let _env = EnvGuard::set("GREENTIC_EXT_ALLOW_UNSIGNED", "1");
    let tmp = tempfile::tempdir().unwrap();
    let creds = write_tempfile(tmp.path(), "creds.json", "{}");
    let config = write_tempfile(tmp.path(), "config.json", "{}");
    let reg = build_fixture_registry();
    let mut invoker = MockInvoker::default();
    invoker.schemas_creds.insert(
        (
            "greentic.deploy-testfixture".into(),
            "testfixture-noop".into(),
        ),
        r#"{"type":"object"}"#.into(),
    );
    invoker.schemas_config.insert(
        (
            "greentic.deploy-testfixture".into(),
            "testfixture-noop".into(),
        ),
        r#"{"type":"object"}"#.into(),
    );
    let args = ExtApplyArgs {
        target: "testfixture-noop".into(),
        creds,
        config,
        pack: None,
        strict_validate: false,
    };
    let err = run_apply_with_invoker(args, &reg, &invoker).unwrap_err();
    assert!(
        matches!(err, ExtensionError::AdapterNotImplemented { .. }),
        "got: {err:?}"
    );
}

#[test]
fn ext_apply_missing_creds_file_propagates_creds_read_error() {
    let _env = EnvGuard::set("GREENTIC_EXT_ALLOW_UNSIGNED", "1");
    let tmp = tempfile::tempdir().unwrap();
    let config = write_tempfile(tmp.path(), "config.json", "{}");
    let reg = build_fixture_registry();
    let invoker = MockInvoker::default();
    let args = ExtApplyArgs {
        target: "testfixture-noop".into(),
        creds: tmp.path().join("no-such.json"),
        config,
        pack: None,
        strict_validate: false,
    };
    let err = run_apply_with_invoker(args, &reg, &invoker).unwrap_err();
    assert!(
        matches!(err, ExtensionError::CredsReadError { .. }),
        "got: {err:?}"
    );
}

#[test]
#[ignore = "unignore when deploy-aws fixture lands in testdata/ext/ (Phase B #4c follow-up)"]
fn ext_apply_aws_target_requires_required_config_fields() {
    let _env = EnvGuard::set("GREENTIC_EXT_ALLOW_UNSIGNED", "1");
    let tmp = tempfile::tempdir().unwrap();
    let creds = write_tempfile(tmp.path(), "creds.json", "{}");
    // Missing required fields (only region provided)
    let config = write_tempfile(tmp.path(), "config.json", r#"{"region":"us-east-1"}"#);
    let args = ExtApplyArgs {
        target: "aws-ecs-fargate-local".into(),
        creds,
        config,
        pack: None,
        strict_validate: false,
    };
    // Requires testdata/ext/greentic.deploy-aws-stub/ with describe.json + WASM.
    // Currently ignored; will be unignored after #4c publishes deploy-aws@0.1.0
    // and we copy a stub into this repo's testdata/.
    let err = run_apply(&fixture_dir(), args).unwrap_err();
    // Either ValidationFailed (schema) or TargetNotFound depending on fixture state
    assert!(
        matches!(
            err,
            ExtensionError::ValidationFailed { .. } | ExtensionError::TargetNotFound(_)
        ),
        "got: {err:?}"
    );
}

#[test]
#[ignore = "unignore when deploy-gcp fixture lands in testdata/ext/ (Phase B #4d follow-up)"]
fn ext_apply_gcp_target_requires_required_config_fields() {
    let _env = EnvGuard::set("GREENTIC_EXT_ALLOW_UNSIGNED", "1");
    let tmp = tempfile::tempdir().unwrap();
    let creds = write_tempfile(tmp.path(), "creds.json", "{}");
    // Missing required fields (only region provided)
    let config = write_tempfile(tmp.path(), "config.json", r#"{"region":"us-central1"}"#);
    let args = ExtApplyArgs {
        target: "gcp-cloud-run-local".into(),
        creds,
        config,
        pack: None,
        strict_validate: false,
    };
    // Requires testdata/ext/greentic.deploy-gcp-stub/ with describe.json + WASM.
    // Currently ignored; will be unignored after #4d publishes deploy-gcp@0.1.0
    // and we copy a stub into this repo's testdata/.
    let err = run_apply(&fixture_dir(), args).unwrap_err();
    // Either ValidationFailed (schema) or TargetNotFound depending on fixture state
    assert!(
        matches!(
            err,
            ExtensionError::ValidationFailed { .. } | ExtensionError::TargetNotFound(_)
        ),
        "got: {err:?}"
    );
}

#[test]
#[ignore = "unignore when deploy-azure fixture lands in testdata/ext/ (Phase B #4d Azure follow-up)"]
fn ext_apply_azure_target_requires_required_config_fields() {
    let _env = EnvGuard::set("GREENTIC_EXT_ALLOW_UNSIGNED", "1");
    let tmp = tempfile::tempdir().unwrap();
    let creds = write_tempfile(tmp.path(), "creds.json", "{}");
    let config = write_tempfile(tmp.path(), "config.json", r#"{"location":"eastus"}"#);
    let args = ExtApplyArgs {
        target: "azure-container-apps-local".into(),
        creds,
        config,
        pack: None,
        strict_validate: false,
    };
    let err = run_apply(&fixture_dir(), args).unwrap_err();
    assert!(
        matches!(
            err,
            ExtensionError::ValidationFailed { .. } | ExtensionError::TargetNotFound(_)
        ),
        "got: {err:?}"
    );
}
