//! CLI-level integration test for the airgap update round-trip.
//!
//! Spawns the compiled `greentic-deployer` binary via `std::process::Command`
//! and exercises: env init -> plan-build -> get -> export -> negative-export ->
//! import -> delta-export. Every step runs inside tempdirs with HOME overridden,
//! no network access, and no real user state.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn deployer_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_greentic-deployer"))
}

/// Run a deployer command and return (stdout, stderr, exit status).
/// HOME is always overridden so the binary never touches real user state.
fn run_deployer(
    args: &[&str],
    home: &Path,
    env_vars: &[(&str, &str)],
) -> (String, String, std::process::ExitStatus) {
    let mut cmd = Command::new(deployer_bin());
    cmd.args(args).env("HOME", home);
    for (k, v) in env_vars {
        cmd.env(k, v);
    }
    let output = cmd
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn deployer with args {args:?}: {e}"));
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr, output.status)
}

/// Parse the first JSON line from CLI stdout, panicking with `label` on failure.
fn parse_json(stdout: &str, label: &str) -> serde_json::Value {
    stdout
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .next()
        .unwrap_or_else(|| panic!("no JSON in {label} stdout: {stdout}"))
}

#[test]
fn airgap_cli_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path();

    // Isolated directories.
    let home_dir = base.join("home");
    let store_exp = base.join("store-exp");
    let store_imp = base.join("store-imp");
    let upd_exp = base.join("upd-exp");
    let upd_imp = base.join("upd-imp");
    let out_dir = base.join("out");
    for d in [
        &home_dir, &store_exp, &store_imp, &upd_exp, &upd_imp, &out_dir,
    ] {
        std::fs::create_dir_all(d).unwrap();
    }

    let store_exp_str = store_exp.to_str().unwrap();
    let store_imp_str = store_imp.to_str().unwrap();
    let upd_exp_str = upd_exp.to_str().unwrap();
    let upd_imp_str = upd_imp.to_str().unwrap();

    // 1. env init (export side) — creates a `local` environment.
    let (stdout, stderr, status) = run_deployer(
        &["op", "--store-root", store_exp_str, "env", "init"],
        &home_dir,
        &[],
    );
    assert!(
        status.success(),
        "env init failed: stdout={stdout}\nstderr={stderr}"
    );
    // Parse env id from stdout JSON.
    let init_out = parse_json(&stdout, "env init");
    let env_id = init_out["result"]["environment_id"]
        .as_str()
        .unwrap_or("local");

    // 2. Create a fake binary payload and compute its digest.
    let bin_payload = b"fake-greentic-start-binary-for-e2e-test";
    let bin_file = out_dir.join("fake-binary");
    std::fs::write(&bin_file, bin_payload).unwrap();
    let bin_digest_hex = greentic_update::plan::sha256_hex(bin_payload);
    let bin_digest = format!("sha256:{bin_digest_hex}");

    // 3. plan-build: build a signed plan with one binary artifact.
    let plan_out_dir = out_dir.join("plan");
    std::fs::create_dir_all(&plan_out_dir).unwrap();
    let binary_spec =
        format!("name=gtc,version=9.9.9,target=x86_64-unknown-linux-gnu,digest={bin_digest}");
    let (stdout, stderr, status) = run_deployer(
        &[
            "op",
            "--store-root",
            store_exp_str,
            "updates",
            "plan-build",
            env_id,
            "--sequence",
            "1",
            "--binary",
            &binary_spec,
            "--out-dir",
            plan_out_dir.to_str().unwrap(),
        ],
        &home_dir,
        &[],
    );
    assert!(
        status.success(),
        "plan-build failed: stdout={stdout}\nstderr={stderr}"
    );

    // Verify plan files exist.
    let plan_file = plan_out_dir.join("plan.json");
    let plan_sig_file = plan_out_dir.join("plan.json.sig");
    assert!(plan_file.exists(), "plan.json must exist");
    assert!(plan_sig_file.exists(), "plan.json.sig must exist");

    // 4. get: stage the plan on the export side.
    let (stdout, stderr, status) = run_deployer(
        &[
            "op",
            "--store-root",
            store_exp_str,
            "updates",
            "get",
            env_id,
            "--plan-file",
            plan_file.to_str().unwrap(),
            "--plan-sig-file",
            plan_sig_file.to_str().unwrap(),
        ],
        &home_dir,
        &[("GREENTIC_UPDATES_DIR", upd_exp_str)],
    );
    assert!(
        status.success(),
        "updates get failed: stdout={stdout}\nstderr={stderr}"
    );

    // Parse plan_id from get output.
    let get_out = parse_json(&stdout, "updates get");
    let plan_id = get_out["result"]["plan_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no plan_id in get output: {get_out}"));

    // 5. export: full export with --binary-blob.
    let envelope_path = out_dir.join("update.gtupdate");
    let (stdout, stderr, status) = run_deployer(
        &[
            "op",
            "--store-root",
            store_exp_str,
            "updates",
            "export",
            env_id,
            "--plan-id",
            plan_id,
            "--out",
            envelope_path.to_str().unwrap(),
            "--binary-blob",
            bin_file.to_str().unwrap(),
        ],
        &home_dir,
        &[("GREENTIC_UPDATES_DIR", upd_exp_str)],
    );
    assert!(
        status.success(),
        "export failed: stdout={stdout}\nstderr={stderr}"
    );
    assert!(envelope_path.exists(), "envelope file must exist");

    // Parse and verify export output fields.
    let export_out = parse_json(&stdout, "export");
    assert!(
        export_out["result"]["blobs_included"].as_u64().unwrap() > 0,
        "export must include at least one blob"
    );
    assert_eq!(
        export_out["result"]["blobs_skipped"].as_u64().unwrap(),
        0,
        "full export skips nothing"
    );

    // 6. Negative: export on a FRESH updates dir WITHOUT --binary-blob.
    let upd_exp2 = base.join("upd-exp2");
    std::fs::create_dir_all(&upd_exp2).unwrap();
    let upd_exp2_str = upd_exp2.to_str().unwrap();

    // Re-get the plan into the fresh updates dir (so it has the plan but not the blob).
    let (stdout2, stderr2, status2) = run_deployer(
        &[
            "op",
            "--store-root",
            store_exp_str,
            "updates",
            "get",
            env_id,
            "--plan-file",
            plan_file.to_str().unwrap(),
            "--plan-sig-file",
            plan_sig_file.to_str().unwrap(),
        ],
        &home_dir,
        &[("GREENTIC_UPDATES_DIR", upd_exp2_str)],
    );
    assert!(
        status2.success(),
        "second get failed: stdout={stdout2}\nstderr={stderr2}"
    );

    let neg_envelope = out_dir.join("should-not-exist.gtupdate");
    let (_stdout, stderr, status) = run_deployer(
        &[
            "op",
            "--store-root",
            store_exp_str,
            "updates",
            "export",
            env_id,
            "--plan-id",
            plan_id,
            "--out",
            neg_envelope.to_str().unwrap(),
        ],
        &home_dir,
        &[("GREENTIC_UPDATES_DIR", upd_exp2_str)],
    );
    assert!(
        !status.success(),
        "export without --binary-blob should fail"
    );
    assert!(
        stderr.contains(&bin_digest_hex) || stderr.contains("missing on disk"),
        "stderr should mention the missing digest or 'missing on disk': {stderr}"
    );
    assert!(
        !neg_envelope.exists(),
        "no envelope should be written on failure"
    );

    // 7. import on the receiving side with --stage.
    // First, init the import store.
    let (_stdout, _stderr, status) = run_deployer(
        &["op", "--store-root", store_imp_str, "env", "init"],
        &home_dir,
        &[],
    );
    assert!(status.success(), "import-side env init failed");

    // Find trust-root.json from the export store.
    let trust_root = store_exp.join(env_id).join("trust-root.json");
    assert!(
        trust_root.exists(),
        "trust-root.json must exist at {}",
        trust_root.display()
    );

    let (stdout, stderr, status) = run_deployer(
        &[
            "op",
            "--store-root",
            store_imp_str,
            "updates",
            "import",
            env_id,
            "--envelope",
            envelope_path.to_str().unwrap(),
            "--trust-root",
            trust_root.to_str().unwrap(),
            "--stage",
        ],
        &home_dir,
        &[("GREENTIC_UPDATES_DIR", upd_imp_str)],
    );
    assert!(
        status.success(),
        "import failed: stdout={stdout}\nstderr={stderr}"
    );

    // Parse import output.
    let import_out = parse_json(&stdout, "import");
    assert_eq!(
        import_out["result"]["stage"].as_str().unwrap_or(""),
        "staged",
        "import must reach staged"
    );
    assert!(
        import_out["result"]["blobs_imported"].as_u64().unwrap() > 0,
        "import must import at least one blob"
    );

    // Derive receipt paths from import output.
    let receipt_path_str = import_out["result"]["receipt_path"]
        .as_str()
        .unwrap_or_else(|| panic!("no receipt_path in import output: {import_out}"));
    let receipt_path = PathBuf::from(receipt_path_str);
    let receipt_sig_path = PathBuf::from(format!("{receipt_path_str}.sig"));
    assert!(
        receipt_path.exists(),
        "import-receipt.json must exist at {}",
        receipt_path.display()
    );
    assert!(
        receipt_sig_path.exists(),
        "import-receipt.json.sig must exist at {}",
        receipt_sig_path.display()
    );

    // 8. Delta export: use the import receipt to skip held blobs.
    let delta_envelope = out_dir.join("delta.gtupdate");
    let (stdout, stderr, status) = run_deployer(
        &[
            "op",
            "--store-root",
            store_exp_str,
            "updates",
            "export",
            env_id,
            "--plan-id",
            plan_id,
            "--out",
            delta_envelope.to_str().unwrap(),
            "--binary-blob",
            bin_file.to_str().unwrap(),
            "--base-receipt",
            receipt_path.to_str().unwrap(),
            "--base-receipt-sig",
            receipt_sig_path.to_str().unwrap(),
        ],
        &home_dir,
        &[("GREENTIC_UPDATES_DIR", upd_exp_str)],
    );
    assert!(
        status.success(),
        "delta export failed: stdout={stdout}\nstderr={stderr}"
    );
    assert!(delta_envelope.exists(), "delta envelope must exist");

    // Parse delta export output.
    let delta_out = parse_json(&stdout, "delta export");
    assert!(
        delta_out["result"]["blobs_skipped"].as_u64().unwrap() > 0,
        "delta export must skip at least one blob"
    );

    // Delta envelope must be strictly smaller than the full one.
    let full_size = std::fs::metadata(&envelope_path).unwrap().len();
    let delta_size = std::fs::metadata(&delta_envelope).unwrap().len();
    assert!(
        delta_size < full_size,
        "delta ({delta_size}) must be smaller than full ({full_size})"
    );
}

/// Recursively collect every file under `root` into a sorted map of
/// (relative-path, content). Used to snapshot the serving directory so we
/// can detect any mutation — including stray blob writes — after a rejected
/// publish.
fn snapshot_dir(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut map = BTreeMap::new();
    fn walk(dir: &Path, root: &Path, map: &mut BTreeMap<String, Vec<u8>>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, root, map);
                } else {
                    let rel = path
                        .strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .to_string();
                    let content = std::fs::read(&path).unwrap();
                    map.insert(rel, content);
                }
            }
        }
    }
    walk(root, root, &mut map);
    map
}

/// Build a plan at a given sequence, get it, export it, and return the
/// envelope path and the plan_id. Uses the provided export-side store,
/// updates dir, and output dir. The binary spec determines the plan content
/// (and therefore its digest), so passing different binary payloads produces
/// plans with different plan_ids.
#[allow(clippy::too_many_arguments)]
fn build_and_export_plan(
    store_exp: &Path,
    upd_exp: &Path,
    out_dir: &Path,
    home: &Path,
    env_id: &str,
    sequence: u64,
    bin_file: &Path,
    bin_digest: &str,
    label: &str,
) -> (PathBuf, String) {
    let plan_out = out_dir.join(format!("plan-{label}"));
    std::fs::create_dir_all(&plan_out).unwrap();

    let binary_spec =
        format!("name=gtc,version=9.9.9,target=x86_64-unknown-linux-gnu,digest={bin_digest}");
    let seq_str = sequence.to_string();
    let (stdout, stderr, status) = run_deployer(
        &[
            "op",
            "--store-root",
            store_exp.to_str().unwrap(),
            "updates",
            "plan-build",
            env_id,
            "--sequence",
            &seq_str,
            "--binary",
            &binary_spec,
            "--out-dir",
            plan_out.to_str().unwrap(),
        ],
        home,
        &[],
    );
    assert!(
        status.success(),
        "{label} plan-build failed: stdout={stdout}\nstderr={stderr}"
    );

    let plan_file = plan_out.join("plan.json");
    let plan_sig_file = plan_out.join("plan.json.sig");

    let upd_exp_str = upd_exp.to_str().unwrap();

    // get: stage the plan on the export side.
    let (stdout, stderr, status) = run_deployer(
        &[
            "op",
            "--store-root",
            store_exp.to_str().unwrap(),
            "updates",
            "get",
            env_id,
            "--plan-file",
            plan_file.to_str().unwrap(),
            "--plan-sig-file",
            plan_sig_file.to_str().unwrap(),
        ],
        home,
        &[("GREENTIC_UPDATES_DIR", upd_exp_str)],
    );
    assert!(
        status.success(),
        "{label} get failed: stdout={stdout}\nstderr={stderr}"
    );

    let get_out = parse_json(&stdout, &format!("{label} get"));
    let plan_id = get_out["result"]["plan_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no plan_id in {label} get output: {get_out}"))
        .to_string();

    // export: produce an envelope with blobs.
    let envelope_path = out_dir.join(format!("{label}.gtupdate"));
    let (stdout, stderr, status) = run_deployer(
        &[
            "op",
            "--store-root",
            store_exp.to_str().unwrap(),
            "updates",
            "export",
            env_id,
            "--plan-id",
            &plan_id,
            "--out",
            envelope_path.to_str().unwrap(),
            "--binary-blob",
            bin_file.to_str().unwrap(),
        ],
        home,
        &[("GREENTIC_UPDATES_DIR", upd_exp_str)],
    );
    assert!(
        status.success(),
        "{label} export failed: stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        envelope_path.exists(),
        "{label} envelope must exist at {}",
        envelope_path.display()
    );

    (envelope_path, plan_id)
}

/// Prove that --push-to behaves correctly across multiple imports:
/// monotonic sequence guard, full wire contract, and no corruption on
/// rejected publishes.
#[test]
fn tier2_push_to_monotonic_multi_import() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path();

    // Shared directories.
    let home_dir = base.join("home");
    let store_exp = base.join("store-exp");
    let upd_exp = base.join("upd-exp");
    let out_dir = base.join("out");
    let push_to_dir = base.join("push-to");
    std::fs::create_dir_all(&home_dir).unwrap();
    std::fs::create_dir_all(&store_exp).unwrap();
    std::fs::create_dir_all(&upd_exp).unwrap();
    std::fs::create_dir_all(&out_dir).unwrap();

    // Each import gets its own store and updates dir to avoid FSM conflicts.
    let store_imp1 = base.join("store-imp1");
    let store_imp2 = base.join("store-imp2");
    let store_imp3 = base.join("store-imp3");
    let store_imp4 = base.join("store-imp4");
    let upd_imp1 = base.join("upd-imp1");
    let upd_imp2 = base.join("upd-imp2");
    let upd_imp3 = base.join("upd-imp3");
    let upd_imp4 = base.join("upd-imp4");
    for d in [
        &store_imp1,
        &store_imp2,
        &store_imp3,
        &store_imp4,
        &upd_imp1,
        &upd_imp2,
        &upd_imp3,
        &upd_imp4,
    ] {
        std::fs::create_dir_all(d).unwrap();
    }

    let store_exp_str = store_exp.to_str().unwrap();

    // --- env init (export side) ---
    let (stdout, stderr, status) = run_deployer(
        &["op", "--store-root", store_exp_str, "env", "init"],
        &home_dir,
        &[],
    );
    assert!(
        status.success(),
        "env init failed: stdout={stdout}\nstderr={stderr}"
    );
    let init_out = parse_json(&stdout, "env init");
    let env_id = init_out["result"]["environment_id"]
        .as_str()
        .unwrap_or("local");

    // Init import stores.
    for s in [&store_imp1, &store_imp2, &store_imp3, &store_imp4] {
        let (_, stderr, status) = run_deployer(
            &["op", "--store-root", s.to_str().unwrap(), "env", "init"],
            &home_dir,
            &[],
        );
        assert!(status.success(), "import-side env init failed: {stderr}");
    }

    // Trust root from the export store.
    let trust_root = store_exp.join(env_id).join("trust-root.json");
    assert!(
        trust_root.exists(),
        "trust-root.json must exist at {}",
        trust_root.display()
    );

    // Create two distinct binary payloads so we can produce plans with
    // different digests (and therefore different plan_ids).
    let bin_payload_a = b"fake-binary-payload-A-for-push-to-e2e";
    let bin_file_a = out_dir.join("binary-a");
    std::fs::write(&bin_file_a, bin_payload_a).unwrap();
    let bin_digest_a = format!(
        "sha256:{}",
        greentic_update::plan::sha256_hex(bin_payload_a)
    );

    let bin_payload_b = b"fake-binary-payload-B-for-push-to-e2e-different";
    let bin_file_b = out_dir.join("binary-b");
    std::fs::write(&bin_file_b, bin_payload_b).unwrap();
    let bin_digest_b = format!(
        "sha256:{}",
        greentic_update::plan::sha256_hex(bin_payload_b)
    );

    // Build three plans: seq 1 (payload A), seq 2 (payload A), seq 1 (payload A again).
    // Also build a fourth plan for the same-sequence-different-digest case:
    // seq 2 with payload B (different plan digest).
    let (envelope1, _plan_id1) = build_and_export_plan(
        &store_exp,
        &upd_exp,
        &out_dir,
        &home_dir,
        env_id,
        1,
        &bin_file_a,
        &bin_digest_a,
        "seq1",
    );
    let (envelope2, _plan_id2) = build_and_export_plan(
        &store_exp,
        &upd_exp,
        &out_dir,
        &home_dir,
        env_id,
        2,
        &bin_file_a,
        &bin_digest_a,
        "seq2",
    );
    let (envelope3, _plan_id3) = build_and_export_plan(
        &store_exp,
        &upd_exp,
        &out_dir,
        &home_dir,
        env_id,
        1,
        &bin_file_a,
        &bin_digest_a,
        "seq1again",
    );
    let (envelope4, _plan_id4) = build_and_export_plan(
        &store_exp,
        &upd_exp,
        &out_dir,
        &home_dir,
        env_id,
        2,
        &bin_file_b,
        &bin_digest_b,
        "seq2alt",
    );

    let trust_root_str = trust_root.to_str().unwrap();
    let push_to_str = push_to_dir.to_str().unwrap();

    // ---------------------------------------------------------------
    // Import #1: sequence 1 with --push-to
    // ---------------------------------------------------------------
    let (stdout, stderr, status) = run_deployer(
        &[
            "op",
            "--store-root",
            store_imp1.to_str().unwrap(),
            "updates",
            "import",
            env_id,
            "--envelope",
            envelope1.to_str().unwrap(),
            "--trust-root",
            trust_root_str,
            "--stage",
            "--push-to",
            push_to_str,
        ],
        &home_dir,
        &[("GREENTIC_UPDATES_DIR", upd_imp1.to_str().unwrap())],
    );
    assert!(
        status.success(),
        "import #1 failed: stdout={stdout}\nstderr={stderr}"
    );

    // (a) After import #1: plan/meta sequence == 1.
    let meta_path = push_to_dir.join("plan").join("meta");
    let meta_bytes = std::fs::read(&meta_path)
        .unwrap_or_else(|e| panic!("plan/meta missing after import #1: {e}"));
    let meta: serde_json::Value = serde_json::from_slice(&meta_bytes)
        .unwrap_or_else(|e| panic!("plan/meta not valid JSON after import #1: {e}"));
    assert_eq!(
        meta["sequence"].as_u64().unwrap(),
        1,
        "after import #1, sequence must be 1"
    );

    // ---------------------------------------------------------------
    // Import #2: sequence 2 with --push-to (upgrade)
    // ---------------------------------------------------------------
    let (stdout, stderr, status) = run_deployer(
        &[
            "op",
            "--store-root",
            store_imp2.to_str().unwrap(),
            "updates",
            "import",
            env_id,
            "--envelope",
            envelope2.to_str().unwrap(),
            "--trust-root",
            trust_root_str,
            "--stage",
            "--push-to",
            push_to_str,
        ],
        &home_dir,
        &[("GREENTIC_UPDATES_DIR", upd_imp2.to_str().unwrap())],
    );
    assert!(
        status.success(),
        "import #2 failed: stdout={stdout}\nstderr={stderr}"
    );

    // (b) Full wire contract after import #2.
    let meta_bytes_2 = std::fs::read(&meta_path)
        .unwrap_or_else(|e| panic!("plan/meta missing after import #2: {e}"));
    let meta2: serde_json::Value = serde_json::from_slice(&meta_bytes_2)
        .unwrap_or_else(|e| panic!("plan/meta not valid JSON after import #2: {e}"));

    // Sequence must be 2.
    assert_eq!(
        meta2["sequence"].as_u64().unwrap(),
        2,
        "after import #2, sequence must be 2"
    );

    // meta must have EXACTLY two fields: sequence and plan_sha256.
    let meta2_obj = meta2.as_object().unwrap();
    assert_eq!(
        meta2_obj.len(),
        2,
        "meta must have exactly 2 fields, got: {:?}",
        meta2_obj.keys().collect::<Vec<_>>()
    );
    assert!(
        meta2_obj.contains_key("sequence"),
        "meta must contain 'sequence'"
    );
    assert!(
        meta2_obj.contains_key("plan_sha256"),
        "meta must contain 'plan_sha256'"
    );

    // sha256(plan/plan.json) must equal meta.plan_sha256.
    let plan_json_path = push_to_dir.join("plan").join("plan.json");
    let plan_json_bytes = std::fs::read(&plan_json_path)
        .unwrap_or_else(|e| panic!("plan/plan.json missing after import #2: {e}"));
    let actual_sha256 = greentic_update::plan::sha256_hex(&plan_json_bytes);
    let expected_sha256 = meta2["plan_sha256"].as_str().unwrap();
    assert_eq!(
        actual_sha256, expected_sha256,
        "sha256(plan.json) must match meta.plan_sha256"
    );

    // plan.json.sig must exist and be non-empty.
    let plan_sig_path = push_to_dir.join("plan").join("plan.json.sig");
    let sig_bytes = std::fs::read(&plan_sig_path)
        .unwrap_or_else(|e| panic!("plan/plan.json.sig missing after import #2: {e}"));
    assert!(
        !sig_bytes.is_empty(),
        "plan/plan.json.sig must be non-empty"
    );

    // Every binary digest in the plan must have a blob file whose content
    // matches the exported binary.
    let plan_value: serde_json::Value = serde_json::from_slice(&plan_json_bytes)
        .unwrap_or_else(|e| panic!("plan/plan.json not valid JSON: {e}"));
    let blobs_dir = push_to_dir.join("blobs");
    // Check binaries array.
    if let Some(binaries) = plan_value["binaries"].as_array() {
        for b in binaries {
            let digest_str = b["digest"].as_str().unwrap();
            let blob_filename = digest_str.replacen(':', "-", 1);
            let blob_path = blobs_dir.join(&blob_filename);
            assert!(
                blob_path.exists(),
                "blob file must exist at {} for digest {digest_str}",
                blob_path.display()
            );
            let blob_content = std::fs::read(&blob_path).unwrap();
            assert!(
                !blob_content.is_empty(),
                "blob file for {digest_str} must be non-empty"
            );
            // Verify the blob's content actually hashes to the digest.
            let content_hash = greentic_update::plan::sha256_hex(&blob_content);
            let expected_hex = digest_str.strip_prefix("sha256:").unwrap_or(digest_str);
            assert_eq!(
                content_hash, expected_hex,
                "blob content hash must match digest {digest_str}"
            );
        }
    }
    // Check artifacts array.
    if let Some(artifacts) = plan_value["artifacts"].as_array() {
        for a in artifacts {
            let digest_str = a["digest"].as_str().unwrap();
            let blob_filename = digest_str.replacen(':', "-", 1);
            let blob_path = blobs_dir.join(&blob_filename);
            assert!(
                blob_path.exists(),
                "blob file must exist at {} for artifact digest {digest_str}",
                blob_path.display()
            );
        }
    }

    // Snapshot the push-to state after import #2 for later comparison.
    let plan_json_after_2 = plan_json_bytes.clone();
    let plan_sig_after_2 = sig_bytes.clone();
    let meta_after_2 = meta_bytes_2.clone();
    // Full-tree snapshot: catches stray blob writes that the per-file checks miss.
    let serving_snapshot_after_2 = snapshot_dir(&push_to_dir);

    // ---------------------------------------------------------------
    // Import #3: sequence 1 with --push-to (MUST fail: downgrade)
    // ---------------------------------------------------------------
    let (_stdout, stderr, status) = run_deployer(
        &[
            "op",
            "--store-root",
            store_imp3.to_str().unwrap(),
            "updates",
            "import",
            env_id,
            "--envelope",
            envelope3.to_str().unwrap(),
            "--trust-root",
            trust_root_str,
            "--stage",
            "--push-to",
            push_to_str,
        ],
        &home_dir,
        &[("GREENTIC_UPDATES_DIR", upd_imp3.to_str().unwrap())],
    );
    // (c) Must fail with non-zero exit.
    assert!(
        !status.success(),
        "import #3 (downgrade seq 2 -> 1) must fail"
    );
    // Stderr must mention the downgrade refusal.
    assert!(
        stderr.contains("refusing downgrade to sequence"),
        "stderr must mention downgrade refusal, got: {stderr}"
    );
    // Stderr must also say the import itself committed.
    assert!(
        stderr.contains("import committed successfully (receipt written)"),
        "stderr must say import committed, got: {stderr}"
    );

    // (d) CRITICAL: push-to directory must be unchanged after the failed import.
    let plan_json_after_3 = std::fs::read(&plan_json_path)
        .unwrap_or_else(|e| panic!("plan/plan.json missing after import #3: {e}"));
    assert_eq!(
        plan_json_after_3, plan_json_after_2,
        "plan/plan.json must be byte-identical after rejected import #3"
    );
    let plan_sig_after_3 = std::fs::read(&plan_sig_path)
        .unwrap_or_else(|e| panic!("plan/plan.json.sig missing after import #3: {e}"));
    assert_eq!(
        plan_sig_after_3, plan_sig_after_2,
        "plan/plan.json.sig must be byte-identical after rejected import #3"
    );
    let meta_after_3 = std::fs::read(&meta_path)
        .unwrap_or_else(|e| panic!("plan/meta missing after import #3: {e}"));
    assert_eq!(
        meta_after_3, meta_after_2,
        "plan/meta must be byte-identical after rejected import #3"
    );
    let meta3: serde_json::Value = serde_json::from_slice(&meta_after_3).unwrap();
    assert_eq!(
        meta3["sequence"].as_u64().unwrap(),
        2,
        "plan/meta sequence must still be 2 after rejected downgrade"
    );
    // Full-tree check: no stray files (e.g. blobs) written before the reject.
    assert_eq!(
        snapshot_dir(&push_to_dir),
        serving_snapshot_after_2,
        "complete serving directory (plan + blobs) must be unchanged after rejected import #3"
    );

    // ---------------------------------------------------------------
    // Import #4: same sequence 2, different plan digest (MUST fail:
    // fleet-splitting guard)
    // ---------------------------------------------------------------
    let (_stdout, stderr4, status4) = run_deployer(
        &[
            "op",
            "--store-root",
            store_imp4.to_str().unwrap(),
            "updates",
            "import",
            env_id,
            "--envelope",
            envelope4.to_str().unwrap(),
            "--trust-root",
            trust_root_str,
            "--stage",
            "--push-to",
            push_to_str,
        ],
        &home_dir,
        &[("GREENTIC_UPDATES_DIR", upd_imp4.to_str().unwrap())],
    );
    assert!(
        !status4.success(),
        "import #4 (same seq, different digest) must fail"
    );
    assert!(
        stderr4.contains("same sequence with a different plan"),
        "stderr must mention same-sequence conflict, got: {stderr4}"
    );
    assert!(
        stderr4.contains("import committed successfully (receipt written)"),
        "stderr must say import committed for #4, got: {stderr4}"
    );

    // Push-to directory must still be unchanged.
    let plan_json_after_4 = std::fs::read(&plan_json_path)
        .unwrap_or_else(|e| panic!("plan/plan.json missing after import #4: {e}"));
    assert_eq!(
        plan_json_after_4, plan_json_after_2,
        "plan/plan.json must be byte-identical after rejected import #4"
    );
    let plan_sig_after_4 = std::fs::read(&plan_sig_path)
        .unwrap_or_else(|e| panic!("plan/plan.json.sig missing after import #4: {e}"));
    assert_eq!(
        plan_sig_after_4, plan_sig_after_2,
        "plan/plan.json.sig must be byte-identical after rejected import #4"
    );
    let meta_after_4 = std::fs::read(&meta_path)
        .unwrap_or_else(|e| panic!("plan/meta missing after import #4: {e}"));
    assert_eq!(
        meta_after_4, meta_after_2,
        "plan/meta must be byte-identical after rejected import #4"
    );
    // Full-tree check: import #4 uses a different payload (binary B), so an
    // implementation that writes the new blob before rejecting the
    // same-sequence conflict would leave a stray file here.
    assert_eq!(
        snapshot_dir(&push_to_dir),
        serving_snapshot_after_2,
        "complete serving directory (plan + blobs) must be unchanged after rejected import #4"
    );
}
