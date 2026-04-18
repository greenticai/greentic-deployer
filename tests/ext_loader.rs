#![cfg(feature = "extensions")]

#[path = "support/env_guard.rs"]
mod env_guard;

use env_guard::EnvGuard;
use greentic_deployer::ext::loader::scan;
use std::path::PathBuf;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/ext")
}

#[test]
fn loader_discovers_in_repo_fixture() {
    let _env = EnvGuard::set("GREENTIC_EXT_ALLOW_UNSIGNED", "1");
    let v = scan(&fixture_dir()).expect("scan");
    assert!(
        v.iter()
            .any(|e| e.describe.metadata.id == "greentic.deploy-testfixture"),
        "expected testfixture to be discovered; got {:?}",
        v.iter()
            .map(|e| &e.describe.metadata.id)
            .collect::<Vec<_>>()
    );
    let ext = v
        .iter()
        .find(|e| e.describe.metadata.id == "greentic.deploy-testfixture")
        .unwrap();
    assert_eq!(ext.describe.contributions.targets.len(), 1);
    assert_eq!(ext.describe.contributions.targets[0].id, "testfixture-noop");
}
