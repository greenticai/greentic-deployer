//! CLI-level integration test for the airgap update round-trip.
//!
//! Spawns the compiled `greentic-deployer` binary via `std::process::Command`
//! and exercises: env init -> plan-build -> get -> export -> negative-export ->
//! import -> delta-export. Every step runs inside tempdirs with HOME overridden,
//! no network access, and no real user state.

use sha2::{Digest, Sha256};
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

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
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
    let init_out: serde_json::Value = stdout
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .next()
        .unwrap_or_else(|| panic!("no JSON in env init stdout: {stdout}"));
    let env_id = init_out["result"]["environment_id"]
        .as_str()
        .unwrap_or("local");

    // 2. Create a fake binary payload and compute its digest.
    let bin_payload = b"fake-greentic-start-binary-for-e2e-test";
    let bin_file = out_dir.join("fake-binary");
    std::fs::write(&bin_file, bin_payload).unwrap();
    let bin_digest_hex = sha256_hex(bin_payload);
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
    let get_out: serde_json::Value = stdout
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .next()
        .unwrap_or_else(|| panic!("no JSON in updates get stdout: {stdout}"));
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
    let export_out: serde_json::Value = stdout
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .next()
        .unwrap_or_else(|| panic!("no JSON in export stdout: {stdout}"));
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
    let import_out: serde_json::Value = stdout
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .next()
        .unwrap_or_else(|| panic!("no JSON in import stdout: {stdout}"));
    assert_eq!(
        import_out["result"]["stage"].as_str().unwrap_or(""),
        "staged",
        "import must reach staged"
    );
    assert!(
        import_out["result"]["blobs_imported"].as_u64().unwrap() > 0,
        "import must import at least one blob"
    );

    // Verify receipt files exist.
    let receipt_path = upd_imp.join(env_id).join("import-receipt.json");
    let receipt_sig_path = upd_imp.join(env_id).join("import-receipt.json.sig");
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
    let delta_out: serde_json::Value = stdout
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .next()
        .unwrap_or_else(|| panic!("no JSON in delta export stdout: {stdout}"));
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
