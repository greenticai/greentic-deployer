//! Stage-time `pack-config-input.v1` → `pack-config.v1` materializer (C7 PR4).
//!
//! Wizards (greentic-setup PR2 / operator + start PR3) emit one
//! `pack-config-input.v1` file per provider under
//! `<bundle_root>/state/pack-configs/<pack_id>.json`. Those files travel inside
//! the `.gtbundle` squashfs. At revision-create the deployer:
//!
//! 1. Extracts the bundle under `<rev_dir>/bundle/` (via [`super::bundle_stage`]).
//! 2. Scans `<rev_dir>/bundle/state/pack-configs/*.json`.
//! 3. Validates each input (schema, `secret_refs` URIs).
//! 4. Stamps the active `revision_id` and writes the final
//!    `greentic.pack-config.v1` document under `<rev_dir>/pack-configs/<pack_id>.json`.
//!
//! The env-relative paths returned here are recorded on
//! [`greentic_deploy_spec::Revision::pack_config_refs`], which
//! [`crate::environment::materialize_runtime_config`] surfaces in each
//! revision's `pack_config_refs` so `greentic-start` can resolve them through
//! the C4 runtime-config channel.

use std::path::{Path, PathBuf};

use greentic_deploy_spec::{PackConfig, PackId, RevisionId, SchemaVersion, SecretRef};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::environment::atomic_write::atomic_write_json;

use super::OpError;

/// Schema discriminator the wizard writes; the deployer is the only consumer.
const PACK_CONFIG_INPUT_SCHEMA: &str = "greentic.pack-config-input.v1";

/// Relative directory inside the extracted bundle where wizard outputs land.
/// Mirrors `greentic_setup::qa::persist::PACK_CONFIG_INPUT_DIR`.
const INPUT_DIR_REL: &str = "state/pack-configs";

/// Directory under the revision root where finalized `pack-config.v1`
/// documents are written.
const OUTPUT_DIR_REL: &str = "pack-configs";

/// Wizard-emitted intermediate file the deployer picks up at revision-create.
///
/// Mirrored from `greentic_setup::qa::persist::PackConfigInput` rather than
/// imported: the deployer sits below `greentic-setup` in the tier graph and
/// must stay self-contained. Operator + start also mirror this shape — keeping
/// all three in lockstep is the C7 mirror discipline. Any field change to the
/// wizard-side struct lands across four repos together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PackConfigInput {
    schema: String,
    pack_id: String,
    env_id: String,
    bundle_id: String,
    #[serde(default)]
    non_secret: BTreeMap<String, Value>,
    #[serde(default)]
    secret_refs: BTreeMap<String, String>,
}

/// Materialize finalized `pack-config.v1` documents from any
/// `pack-config-input.v1` files embedded in the extracted bundle.
///
/// Returns env-relative paths (sorted by pack_id for determinism) to record
/// on [`greentic_deploy_spec::Revision::pack_config_refs`]. An empty vec is
/// returned when the bundle ships no inputs — legacy bundles still stage.
///
/// Errors (malformed input file, bad secret URI, write failure) are returned
/// verbatim; the caller's revision-dir rollback already handles partial
/// writes under `<rev_dir>/pack-configs/`.
pub fn materialize_pack_configs(
    env_dir: &Path,
    rev_dir: &Path,
    revision_id: RevisionId,
) -> Result<Vec<PathBuf>, OpError> {
    let input_dir = rev_dir.join("bundle").join(INPUT_DIR_REL);
    if !input_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut inputs: Vec<PathBuf> = std::fs::read_dir(&input_dir)
        .map_err(|source| OpError::Io {
            path: input_dir.clone(),
            source,
        })?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let file_type = entry.file_type().ok()?;
            let path = entry.path();
            if file_type.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                Some(path)
            } else {
                None
            }
        })
        .collect();
    inputs.sort();

    if inputs.is_empty() {
        return Ok(Vec::new());
    }

    let output_dir = rev_dir.join(OUTPUT_DIR_REL);
    std::fs::create_dir_all(&output_dir).map_err(|source| OpError::Io {
        path: output_dir.clone(),
        source,
    })?;

    let mut refs = Vec::with_capacity(inputs.len());
    let mut seen_pack_ids = std::collections::HashSet::with_capacity(inputs.len());
    for input_path in &inputs {
        let body = std::fs::read(input_path).map_err(|source| OpError::Io {
            path: input_path.clone(),
            source,
        })?;
        let input: PackConfigInput = serde_json::from_slice(&body).map_err(|err| {
            OpError::InvalidArgument(format!(
                "pack-config-input `{}`: {err}",
                input_path.display()
            ))
        })?;

        if input.schema != PACK_CONFIG_INPUT_SCHEMA {
            return Err(OpError::InvalidArgument(format!(
                "pack-config-input `{}`: unexpected schema `{}` (want `{}`)",
                input_path.display(),
                input.schema,
                PACK_CONFIG_INPUT_SCHEMA
            )));
        }

        // The file stem and the embedded pack_id must agree. A mismatch means
        // a bundle was hand-edited or a wizard regressed — either way the
        // deployer must not silently pick one and ignore the other.
        let stem = input_path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| {
                OpError::InvalidArgument(format!(
                    "pack-config-input `{}`: file has no UTF-8 stem",
                    input_path.display()
                ))
            })?;
        if stem != input.pack_id {
            return Err(OpError::InvalidArgument(format!(
                "pack-config-input `{}`: file stem `{stem}` disagrees with embedded pack_id `{}`",
                input_path.display(),
                input.pack_id
            )));
        }

        if !seen_pack_ids.insert(input.pack_id.clone()) {
            return Err(OpError::InvalidArgument(format!(
                "pack-config-input `{}`: duplicate pack_id `{}` in bundle",
                input_path.display(),
                input.pack_id
            )));
        }

        let mut secret_refs = BTreeMap::new();
        for (key, raw) in input.secret_refs {
            let parsed = SecretRef::try_new(&raw).map_err(|err| {
                OpError::InvalidArgument(format!(
                    "pack-config-input `{}`: secret_refs.{key} = `{raw}` is not a valid `secret://` URI ({err:?})",
                    input_path.display()
                ))
            })?;
            secret_refs.insert(key, parsed);
        }

        let pack_config = PackConfig {
            schema: SchemaVersion::new(SchemaVersion::PACK_CONFIG_V1),
            pack_id: PackId::new(&input.pack_id),
            revision_id,
            non_secret: input.non_secret,
            secret_refs,
            runtime_refs: BTreeMap::new(),
        };

        let out_path = output_dir.join(format!("{}.json", input.pack_id));
        atomic_write_json(&out_path, &pack_config)
            .map_err(|e| OpError::Store(crate::environment::store::StoreError::from(e)))?;

        let rel = out_path
            .strip_prefix(env_dir)
            .map_err(|_| {
                OpError::InvalidArgument(format!(
                    "pack-config `{}` escaped the env directory",
                    out_path.display()
                ))
            })?
            .to_path_buf();
        refs.push(rel);
    }

    Ok(refs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    fn write_input(extract_dir: &Path, body: &serde_json::Value, file_name: &str) {
        let dir = extract_dir.join(INPUT_DIR_REL);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(file_name),
            serde_json::to_string_pretty(body).unwrap(),
        )
        .unwrap();
    }

    fn extract_dir(rev_dir: &Path) -> PathBuf {
        let dir = rev_dir.join("bundle");
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// No `state/pack-configs/` in the bundle is the legacy path; return an
    /// empty ref list so callers leave `pack_config_refs` empty (which the
    /// runtime-config materializer file-check-skips, same as `pack_list_refs`).
    #[test]
    fn missing_input_dir_yields_no_refs() {
        let env = tempdir().unwrap();
        let rev_dir = env.path().join("revisions/r1");
        std::fs::create_dir_all(rev_dir.join("bundle")).unwrap();

        let refs = materialize_pack_configs(env.path(), &rev_dir, RevisionId::new()).unwrap();
        assert!(refs.is_empty());
    }

    /// An empty `state/pack-configs/` directory (no JSON files) returns no
    /// refs and writes no output dir — same fail-safe shape as the missing
    /// directory case.
    #[test]
    fn empty_input_dir_yields_no_refs() {
        let env = tempdir().unwrap();
        let rev_dir = env.path().join("revisions/r1");
        let ext = extract_dir(&rev_dir);
        std::fs::create_dir_all(ext.join(INPUT_DIR_REL)).unwrap();

        let refs = materialize_pack_configs(env.path(), &rev_dir, RevisionId::new()).unwrap();
        assert!(refs.is_empty());
        assert!(!rev_dir.join(OUTPUT_DIR_REL).exists());
    }

    /// Happy path: a single input file produces one `pack-config.v1` document
    /// stamped with `revision_id`, secret URIs parsed into `SecretRef`, and an
    /// env-relative ref returned.
    #[test]
    fn single_input_materializes_pack_config_v1() {
        let env = tempdir().unwrap();
        let rev_dir = env.path().join("revisions/r1");
        let ext = extract_dir(&rev_dir);
        write_input(
            &ext,
            &json!({
                "schema": "greentic.pack-config-input.v1",
                "pack_id": "greentic.support.pack",
                "env_id": "local",
                "bundle_id": "customer.support",
                "non_secret": {"timeout_ms": 5000},
                "secret_refs": {"api_token": "secret://local/customer.support/greentic.support.pack/api_token"},
            }),
            "greentic.support.pack.json",
        );

        let rev_id = RevisionId::new();
        let refs = materialize_pack_configs(env.path(), &rev_dir, rev_id).unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(
            refs[0],
            PathBuf::from("revisions/r1/pack-configs/greentic.support.pack.json")
        );

        let written = std::fs::read_to_string(env.path().join(&refs[0])).unwrap();
        let parsed: PackConfig = serde_json::from_str(&written).unwrap();
        assert_eq!(parsed.schema.as_str(), SchemaVersion::PACK_CONFIG_V1);
        assert_eq!(parsed.revision_id, rev_id);
        assert_eq!(parsed.pack_id.as_str(), "greentic.support.pack");
        assert_eq!(parsed.non_secret.get("timeout_ms"), Some(&json!(5000)));
        assert_eq!(
            parsed.secret_refs.get("api_token").map(|r| r.as_str()),
            Some("secret://local/customer.support/greentic.support.pack/api_token")
        );
        assert!(parsed.runtime_refs.is_empty());
    }

    /// Multiple input files sort lexicographically by pack_id so the resulting
    /// `pack_config_refs` order is deterministic (matches the on-disk layout
    /// callers rely on for ref hashing / diffing).
    #[test]
    fn multiple_inputs_emit_sorted_refs() {
        let env = tempdir().unwrap();
        let rev_dir = env.path().join("revisions/r1");
        let ext = extract_dir(&rev_dir);
        for pack in ["zeta.pack", "alpha.pack", "mu.pack"] {
            write_input(
                &ext,
                &json!({
                    "schema": "greentic.pack-config-input.v1",
                    "pack_id": pack,
                    "env_id": "local",
                    "bundle_id": "b",
                    "non_secret": {"x": 1},
                }),
                &format!("{pack}.json"),
            );
        }

        let refs = materialize_pack_configs(env.path(), &rev_dir, RevisionId::new()).unwrap();
        assert_eq!(refs.len(), 3);
        let names: Vec<_> = refs
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        assert_eq!(names, ["alpha.pack.json", "mu.pack.json", "zeta.pack.json"]);
    }

    /// A wizard regression / hand-edit that ships a wrong schema must fail
    /// stage rather than silently injecting a bad document into runtime config.
    #[test]
    fn unexpected_schema_rejects() {
        let env = tempdir().unwrap();
        let rev_dir = env.path().join("revisions/r1");
        let ext = extract_dir(&rev_dir);
        write_input(
            &ext,
            &json!({
                "schema": "greentic.something-else.v1",
                "pack_id": "p",
                "env_id": "e",
                "bundle_id": "b",
            }),
            "p.json",
        );

        let err = materialize_pack_configs(env.path(), &rev_dir, RevisionId::new()).unwrap_err();
        let OpError::InvalidArgument(msg) = err else {
            panic!("expected InvalidArgument, got {err:?}");
        };
        assert!(msg.contains("unexpected schema"), "msg = {msg}");
    }

    /// A `secret_refs` value that is not a `secret://` URI must fail stage —
    /// the runtime resolver would otherwise refuse it at boot, well past the
    /// point a deterministic local failure would have helped.
    #[test]
    fn bad_secret_ref_rejects() {
        let env = tempdir().unwrap();
        let rev_dir = env.path().join("revisions/r1");
        let ext = extract_dir(&rev_dir);
        write_input(
            &ext,
            &json!({
                "schema": "greentic.pack-config-input.v1",
                "pack_id": "p",
                "env_id": "e",
                "bundle_id": "b",
                "secret_refs": {"k": "not-a-secret-uri"},
            }),
            "p.json",
        );

        let err = materialize_pack_configs(env.path(), &rev_dir, RevisionId::new()).unwrap_err();
        let OpError::InvalidArgument(msg) = err else {
            panic!("expected InvalidArgument, got {err:?}");
        };
        assert!(msg.contains("secret_refs.k"), "msg = {msg}");
    }

    /// Defense in depth: file stem must match embedded `pack_id` so the
    /// on-disk `<pack_id>.json` filename can't be hand-edited to a different
    /// pack than the document claims.
    #[test]
    fn stem_pack_id_mismatch_rejects() {
        let env = tempdir().unwrap();
        let rev_dir = env.path().join("revisions/r1");
        let ext = extract_dir(&rev_dir);
        write_input(
            &ext,
            &json!({
                "schema": "greentic.pack-config-input.v1",
                "pack_id": "embedded",
                "env_id": "e",
                "bundle_id": "b",
            }),
            "filestem.json",
        );

        let err = materialize_pack_configs(env.path(), &rev_dir, RevisionId::new()).unwrap_err();
        let OpError::InvalidArgument(msg) = err else {
            panic!("expected InvalidArgument, got {err:?}");
        };
        assert!(
            msg.contains("disagrees with embedded pack_id"),
            "msg = {msg}"
        );
    }

    /// Malformed JSON (truncated body) fails stage with a clear context, not
    /// a silent skip — `state/pack-configs/` is the deployer's contract with
    /// the wizard.
    #[test]
    fn malformed_input_rejects() {
        let env = tempdir().unwrap();
        let rev_dir = env.path().join("revisions/r1");
        let ext = extract_dir(&rev_dir);
        let dir = ext.join(INPUT_DIR_REL);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("p.json"), b"{ not json").unwrap();

        let err = materialize_pack_configs(env.path(), &rev_dir, RevisionId::new()).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }
}
