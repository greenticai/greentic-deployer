#![cfg(feature = "extensions")]

use greentic_deployer::ext::dispatcher::{DispatchAction, DispatchInput, dispatch_extension};
use greentic_deployer::ext::loader::scan;
use greentic_deployer::ext::registry::ExtensionRegistry;
use greentic_deployer::ext::wasm::MockInvoker;
use greentic_deployer::extension::BuiltinBackendId;
use std::path::PathBuf;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/ext")
}

#[test]
fn dispatch_mode_a_routes_to_terraform_backend_id() {
    let loaded = scan(&fixture_dir()).expect("scan");
    let reg = ExtensionRegistry::build(loaded);
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
    let action = dispatch_extension(
        &reg,
        &invoker,
        DispatchInput {
            target_id: "testfixture-noop",
            creds_json: "{}",
            config_json: "{}",
            strict_validate: false,
        },
    )
    .expect("dispatch");
    match action {
        DispatchAction::Builtin(b) => {
            assert_eq!(b.backend, BuiltinBackendId::Terraform);
            assert!(b.handler.is_none());
        }
    }
}

#[test]
fn dispatch_unknown_target_returns_not_found() {
    let loaded = scan(&fixture_dir()).expect("scan");
    let reg = ExtensionRegistry::build(loaded);
    let invoker = MockInvoker::default();
    let err = dispatch_extension(
        &reg,
        &invoker,
        DispatchInput {
            target_id: "does-not-exist",
            creds_json: "{}",
            config_json: "{}",
            strict_validate: false,
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        greentic_deployer::ext::errors::ExtensionError::TargetNotFound(_)
    ));
}
