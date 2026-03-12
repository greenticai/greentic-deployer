use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct NightlyMatrix {
    schema_version: u64,
    owner: String,
    targets: Vec<NightlyTarget>,
}

#[derive(Debug, Deserialize)]
struct NightlyTarget {
    tier: u8,
    adapter: String,
    mode: String,
    environment: String,
    steps: Vec<String>,
}

fn matrix_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("ci")
        .join("nightly_matrix.json")
}

#[test]
fn nightly_matrix_is_well_formed_and_non_empty() {
    let path = matrix_path();
    let text = fs::read_to_string(&path).expect("read nightly matrix");
    let matrix: NightlyMatrix = serde_json::from_str(&text).expect("parse nightly matrix");

    assert_eq!(matrix.schema_version, 1);
    assert_eq!(matrix.owner, "Dmytro");
    assert!(!matrix.targets.is_empty());
}

#[test]
fn nightly_matrix_covers_expected_adapter_surface() {
    let text = fs::read_to_string(matrix_path()).expect("read nightly matrix");
    let matrix: NightlyMatrix = serde_json::from_str(&text).expect("parse nightly matrix");

    let adapters = matrix
        .targets
        .iter()
        .map(|entry| entry.adapter.as_str())
        .collect::<std::collections::BTreeSet<_>>();

    for expected in [
        "single-vm",
        "terraform",
        "aws",
        "gcp",
        "azure",
        "k8s-raw",
        "helm",
        "operator",
        "serverless",
        "snap",
        "juju-machine",
        "juju-k8s",
    ] {
        assert!(adapters.contains(expected), "missing adapter {expected}");
    }
}

#[test]
fn nightly_matrix_steps_match_target_mode_expectations() {
    let text = fs::read_to_string(matrix_path()).expect("read nightly matrix");
    let matrix: NightlyMatrix = serde_json::from_str(&text).expect("parse nightly matrix");

    for target in matrix.targets {
        assert!(
            (1..=3).contains(&target.tier),
            "invalid tier {}",
            target.tier
        );
        assert!(!target.environment.is_empty(), "missing environment");
        assert!(!target.steps.is_empty(), "missing steps");
        assert!(
            target.mode == "execute" || target.mode == "handoff",
            "invalid mode {}",
            target.mode
        );
        if target.mode == "execute" {
            assert!(
                target.steps.iter().any(|step| step == "apply"),
                "execute target {} must include apply",
                target.adapter
            );
        }
        if target.mode == "handoff" {
            assert!(
                target.steps.iter().any(|step| step == "status"),
                "handoff target {} must include status",
                target.adapter
            );
        }
    }
}
