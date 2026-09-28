use std::io::Write as _;
use std::path::{Path, PathBuf};

use greentic_deploy_spec::{Environment, LockedPack, PackId, PackListLock, SchemaVersion};

use super::*;
use crate::cli::secrets::dev_store_put;
use crate::env_packs::deployer::conformance::build_fixture_env;

const JWT_URI: &str = "secrets://gcp-fixture/default/_/messaging_webchat_gui/jwt_signing_key";

/// A `.gtpack` (zip) declaring one tenant-scoped generated secret and one
/// operator-supplied secret, which must NOT be minted.
fn write_pack(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(format!("{name}.gtpack"));
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&path).expect("create pack"));
    zip.start_file(
        "assets/secret-requirements.json",
        zip::write::SimpleFileOptions::default(),
    )
    .expect("start entry");
    zip.write_all(
        br#"[
          {"key": "jwt_signing_key", "generated": {"length": 20, "scope": {"level": "tenant"}}},
          {"key": "api_token"}
        ]"#,
    )
    .expect("write entry");
    zip.finish().expect("finish pack");
    path
}

/// The fixture env with its first revision's pack-list.lock pointing at one
/// staged pack under `env_dir`.
fn env_with_lock(env_dir: &Path) -> Environment {
    let mut env = build_fixture_env();
    let revision = &mut env.revisions[0];
    let rev_dir = env_dir
        .join("revisions")
        .join(revision.revision_id.to_string());
    std::fs::create_dir_all(&rev_dir).expect("rev dir");
    write_pack(&rev_dir, "messaging-webchat-gui");
    let lock = PackListLock {
        schema: SchemaVersion::new(PackListLock::schema_str()),
        revision_id: revision.revision_id,
        packs: vec![LockedPack {
            pack_id: PackId::new("messaging-webchat-gui"),
            path: PathBuf::from("revisions")
                .join(revision.revision_id.to_string())
                .join("messaging-webchat-gui.gtpack"),
            digest: format!("sha256:{}", "0".repeat(64)),
        }],
    };
    let lock_ref = PathBuf::from("revisions")
        .join(revision.revision_id.to_string())
        .join("pack-list.lock");
    std::fs::write(
        env_dir.join(&lock_ref),
        serde_json::to_vec(&lock).expect("lock json"),
    )
    .expect("write lock");
    revision.pack_list_lock_ref = lock_ref;
    env
}

fn fixture_env_id() -> String {
    build_fixture_env().environment_id.as_str().to_string()
}

#[test]
fn the_plan_names_only_generated_secrets_in_the_writers_canonical_form() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = env_with_lock(dir.path());
    let plans = plan_generated(dir.path(), &env, &env.revisions[0]).expect("plan");
    assert_eq!(plans.len(), 1, "{plans:?}");
    let expected = JWT_URI.replace("gcp-fixture", &fixture_env_id());
    assert_eq!(plans[0].write_uri, expected);
    // Both provider spellings are existence candidates, as greentic-start reads.
    assert!(
        plans[0]
            .candidates
            .iter()
            .any(|c| c.contains("/messaging-webchat-gui/")),
        "{:?}",
        plans[0].candidates
    );
}

#[test]
fn a_revision_without_a_readable_lock_cannot_be_established() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = build_fixture_env();
    let err = plan_generated(dir.path(), &env, &env.revisions[0]).expect_err("no lock");
    assert!(err.contains("pack-list.lock"), "{err}");
}

#[test]
fn minting_writes_once_and_never_re_mints() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = env_with_lock(dir.path());
    let plans = plan_generated(dir.path(), &env, &env.revisions[0]).expect("plan");
    let dev_path = dir.path().join(".greentic/dev/.dev.secrets.env");

    let held = mint_missing(&dev_path, &plans).expect("mint");
    let first = dev_store_get_value(&dev_path, &held[0])
        .expect("read")
        .expect("minted");
    // 20 declared bytes, base64url-encoded (the asset default) without padding.
    assert_eq!(first.len(), 27, "the declared length, encoded");

    let again = mint_missing(&dev_path, &plans).expect("second mint");
    assert_eq!(again, held);
    assert_eq!(
        dev_store_get_value(&dev_path, &held[0]).expect("read"),
        Some(first),
        "an existing generated secret is never re-minted"
    );
}

#[test]
fn an_existing_value_under_the_raw_provider_spelling_is_reused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = env_with_lock(dir.path());
    let plans = plan_generated(dir.path(), &env, &env.revisions[0]).expect("plan");
    let dev_path = dir.path().join(".greentic/dev/.dev.secrets.env");
    let raw = plans[0]
        .candidates
        .iter()
        .find(|c| c.contains("/messaging-webchat-gui/"))
        .expect("raw candidate")
        .clone();
    dev_store_put(&dev_path, &raw, "operator-value").expect("seed raw");

    let held = mint_missing(&dev_path, &plans).expect("mint");
    assert_eq!(held, vec![raw]);
    assert_eq!(
        dev_store_get_value(&dev_path, &plans[0].write_uri).expect("read"),
        None,
        "no duplicate is minted under the other spelling"
    );
}

#[test]
fn the_staged_check_reads_the_bytes_that_will_ship() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dev_path = dir.path().join(".dev.secrets.env");
    dev_store_put(&dev_path, "secrets://e/t/_/p/present", "v").expect("put");
    let bytes = std::fs::read(&dev_path).expect("read store");
    let expected = vec![
        "secrets://e/t/_/p/present".to_string(),
        "secrets://e/t/_/p/absent".to_string(),
    ];
    assert_eq!(
        staged_missing(Some(&bytes), &expected).expect("check"),
        vec!["secrets://e/t/_/p/absent".to_string()]
    );
    assert_eq!(
        staged_missing(None, &expected).expect("check"),
        expected,
        "no staged seed carries nothing"
    );
    assert!(staged_missing(None, &[]).expect("check").is_empty());
}

/// Two stages of one env racing on one dev store mint ONE key: the second
/// finds the first's under the writer lock rather than minting its own.
#[test]
fn concurrent_stages_mint_one_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = env_with_lock(dir.path());
    let plans = plan_generated(dir.path(), &env, &env.revisions[0]).expect("plan");
    let dev_path = dir.path().join(".greentic/dev/.dev.secrets.env");

    let barrier = std::sync::Barrier::new(2);
    let values: Vec<String> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    let held = mint_missing(&dev_path, &plans).expect("mint");
                    dev_store_get_value(&dev_path, &held[0])
                        .expect("read")
                        .expect("present")
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("mint thread"))
            .collect()
    });
    assert_eq!(values[0], values[1], "both stages ship the same key");
}
