use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ReplayIndex {
    schema_version: u32,
    replays: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ScaffoldIndex {
    schema_version: u32,
    answers: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ReplayDoc {
    wizard: String,
    pack_fixture: String,
    capability: String,
    answers: ReplayAnswers,
}

#[derive(Debug, Deserialize)]
struct ReplayAnswers {
    example_request: String,
    expected_output: String,
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let text = fs::read_to_string(path).expect("read json");
    serde_json::from_str(&text).expect("parse json")
}

#[test]
fn replay_index_references_existing_answer_docs() {
    let index: ReplayIndex =
        load_json(&root().join("testdata/answers/deployment-packs/replay-index.json"));
    assert_eq!(index.schema_version, 1);
    for entry in index.replays {
        assert!(root().join(&entry).exists(), "missing replay doc {}", entry);
    }
}

#[test]
fn replay_docs_reference_existing_pack_assets() {
    let index: ReplayIndex =
        load_json(&root().join("testdata/answers/deployment-packs/replay-index.json"));
    for entry in index.replays {
        let path = root().join(&entry);
        let doc: ReplayDoc = load_json(&path);
        assert!(doc.wizard.contains("wizard"));
        assert!(!doc.capability.is_empty());

        let fixture_root = root().join(&doc.pack_fixture);
        assert!(
            fixture_root.exists(),
            "missing pack fixture {}",
            doc.pack_fixture
        );
        assert!(
            fixture_root.join(&doc.answers.example_request).exists(),
            "missing example request {} for {}",
            doc.answers.example_request,
            entry
        );
        assert!(
            fixture_root.join(&doc.answers.expected_output).exists(),
            "missing expected output {} for {}",
            doc.answers.expected_output,
            entry
        );
    }
}

#[test]
fn replay_docs_are_unique_by_fixture_and_capability() {
    let index: ReplayIndex =
        load_json(&root().join("testdata/answers/deployment-packs/replay-index.json"));
    let mut seen = std::collections::BTreeSet::new();
    for entry in index.replays {
        let doc: ReplayDoc = load_json(&root().join(&entry));
        let key = format!(
            "{}::{}::{}",
            doc.pack_fixture, doc.capability, doc.answers.expected_output
        );
        assert!(seen.insert(key), "duplicate replay mapping in {}", entry);
    }
}

#[test]
fn scaffold_answer_index_references_real_wizard_answers() {
    let index: ScaffoldIndex =
        load_json(&root().join("testdata/answers/deployer-scaffolds/index.json"));
    assert_eq!(index.schema_version, 1);
    for entry in index.answers {
        let path = root().join(&entry);
        let json: serde_json::Value = load_json(&path);
        assert_eq!(
            json.get("wizard_id").and_then(|value| value.as_str()),
            Some("greentic-pack.wizard.run"),
            "unexpected wizard id in {}",
            entry
        );
        assert_eq!(
            json.get("schema_id").and_then(|value| value.as_str()),
            Some("greentic-pack.wizard.answers"),
            "unexpected schema id in {}",
            entry
        );
        assert!(
            json.pointer("/answers/pack_dir")
                .and_then(|value| value.as_str())
                .is_some(),
            "missing pack_dir in {}",
            entry
        );
        assert!(
            json.pointer("/answers/extension_edit_answers/supported_ops")
                .and_then(|value| value.as_str())
                .is_some(),
            "missing supported_ops in {}",
            entry
        );
    }
}
