//! The store snapshot shipped to the VM: the local env directory, filtered.
//!
//! greentic-start serves from `<store_root>/<env_id>/`, and a portable copy of
//! that directory (no absolute paths inside it — shown by a path-to-path spike)
//! is what the VM needs. The snapshot is the walk of `<store_root>/<env_id>/`
//! minus a short list of SPECIFIC exclusions, with three files replaced:
//!
//! | rel. to `<env_id>/` | treatment |
//! |---|---|
//! | `backups/`, `audit/` | skipped (local history, not runtime state) |
//! | `revision-signing.key`, `logs/` | skipped (runtime-written state; the VM keeps its own) |
//! | any file named exactly `.lock` or `.dev.secrets.env.lock` | skipped (flock files) |
//! | `revisions/*/bundle.gtbundle` | skipped |
//! | `.greentic/dev/.dev.secrets.env` | **replaced** by the filtered bytes the caller injects (omitted if none) |
//! | `.greentic/state/dev/.dev.secrets.env` | skipped: the runtime's other dev-store candidate, and an unfiltered copy of the same secrets |
//! | `environment.json` | **replaced** by the seed form ([`seed_environment_bytes`], the Cloud Run function) |
//! | `runtime.json` | `listen_addr` rewritten to the configured bind address and port |
//!
//! **Never a glob.** The exclusions are exact names and exact positions. An
//! earlier idea, `*.lock`, also drops `pack-list.lock`, and the result is a VM
//! that answers `/healthz` 200 while every webchat request fails with
//! "deployment ... not known to dispatcher". `pack-list.lock`, `bundle.lock.json`
//! and `bundle-lock.json` are shipped; a test pins it.
//!
//! Files outside `<env_id>/` (other environments, and the runtime's own
//! store-root state) are never read. A
//! symlink anywhere in the tree is refused rather than followed.
//!
//! The dev-store bytes MUST come from the filtered read the Cloud Run lane uses
//! (`cli::env::read_dev_secrets_bytes`, which strips the deployer's own bound
//! credential). This module never reads a `.dev.secrets.env` from disk, so it
//! cannot bypass that filter. A `bundle/.greentic/dev/.dev.secrets.env` inside a
//! revision belongs to the bundle and travels as-is. The dev-store master key is
//! not bound to a host, so the snapshot is secret to anyone holding it: it goes
//! only over SSH, in 0600 files.
//!
//! The output is deterministic (sorted, fixed mtime/owner/modes).

use std::collections::BTreeMap;
use std::path::Path;

use greentic_deploy_spec::{Environment, RevisionId};
use serde_json::Value;

use super::params::SshHostParams;
use super::{STORE_MARKER_FILE, hex_sha256};
use crate::cli::secrets::DEV_STORE_RELATIVE;
use crate::env_packs::deployer::DeployerError;
use crate::environment::seed_environment_bytes;

/// Refuse a snapshot larger than this; the real store is a few MB.
pub const MAX_SNAPSHOT_BYTES: u64 = 256 * 1024 * 1024;

/// The store snapshot shipped to the VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreArchive {
    /// The tar stream, including the content marker.
    pub bytes: Vec<u8>,
    /// SHA-256 (hex) of the archive WITHOUT the marker: the identity of the
    /// store content, recorded on the VM so an unchanged store is not re-sent.
    pub content_sha256: String,
}

/// Inputs for [`build_store_archive`].
pub struct SnapshotInput<'a> {
    pub store_root: &'a Path,
    pub env: &'a Environment,
    pub revision_id: RevisionId,
    pub dev_secrets: Option<&'a [u8]>,
    pub params: &'a SshHostParams,
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Include,
    Skip,
    ReplaceDevStore,
    ReplaceEnvironment,
    PatchRuntime,
}

/// Classify one path relative to `<env_id>/`. Pure, and the whole policy.
fn classify(rel: &[String], is_dir: bool) -> Verdict {
    let name = rel.last().map(String::as_str).unwrap_or_default();
    if !is_dir && (name == ".lock" || name == ".dev.secrets.env.lock") {
        return Verdict::Skip;
    }
    let parts: Vec<&str> = rel.iter().map(String::as_str).collect();
    match parts.as_slice() {
        ["backups"] | ["audit"] => Verdict::Skip,
        // Runtime-written state of the machine it ran on: the signing key must be
        // the VM's own (carried between slots by `steps`), and logs stay local.
        ["revision-signing.key"] | ["logs"] => Verdict::Skip,
        ["revisions", _, "bundle.gtbundle"] if !is_dir => Verdict::Skip,
        [".greentic", "dev", ".dev.secrets.env"] if !is_dir => Verdict::ReplaceDevStore,
        [".greentic", "state", "dev", ".dev.secrets.env"] if !is_dir => Verdict::Skip,
        ["environment.json"] if !is_dir => Verdict::ReplaceEnvironment,
        ["runtime.json"] if !is_dir => Verdict::PatchRuntime,
        _ => Verdict::Include,
    }
}

fn io_err(what: impl std::fmt::Display, e: impl std::fmt::Display) -> DeployerError {
    DeployerError::Provider(format!("ssh-host: reading the local store: {what}: {e}"))
}

/// Build the deterministic store archive for `input.env`.
pub fn build_store_archive(input: &SnapshotInput<'_>) -> Result<StoreArchive, DeployerError> {
    let env_id = input.env.environment_id.as_str();
    let env_dir = input.store_root.join(env_id);
    if !env_dir.is_dir() {
        return Err(DeployerError::Provider(format!(
            "ssh-host: the local store has no directory for env `{env_id}` (looked for {}); \
             run `op env init` first",
            env_dir.display()
        )));
    }

    // path (relative to the snapshot root, `/`-separated) -> content; `None` is
    // a directory.
    let mut entries: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
    entries.insert(env_id.to_string(), None);
    let mut total: u64 = 0;
    walk(
        &env_dir,
        &mut Vec::new(),
        input,
        env_id,
        &mut entries,
        &mut total,
    )?;

    let environment_json =
        seed_environment_bytes(input.env, &[input.revision_id]).map_err(|e| {
            DeployerError::Provider(format!(
                "ssh-host: serializing environment.json for the store snapshot: {e}"
            ))
        })?;
    entries.insert(format!("{env_id}/environment.json"), Some(environment_json));
    if let Some(dev) = input.dev_secrets {
        entries.insert(format!("{env_id}/{DEV_STORE_RELATIVE}"), Some(dev.to_vec()));
    }
    // Every file's parent directories exist in the archive, even ones the walk
    // never saw (the replaced dev-store's `.greentic/dev/`).
    let files: Vec<String> = entries
        .iter()
        .filter(|(_, v)| v.is_some())
        .map(|(k, _)| k.clone())
        .collect();
    for file in files {
        let mut acc = String::new();
        for seg in file.split('/').take(file.split('/').count() - 1) {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(seg);
            entries.entry(acc.clone()).or_insert(None);
        }
    }

    let content = write_tar(&entries)?;
    let content_sha256 = hex_sha256(&content);
    entries.insert(
        STORE_MARKER_FILE.to_string(),
        Some(format!("{content_sha256}\n").into_bytes()),
    );
    Ok(StoreArchive {
        bytes: write_tar(&entries)?,
        content_sha256,
    })
}

fn walk(
    dir: &Path,
    rel: &mut Vec<String>,
    input: &SnapshotInput<'_>,
    env_id: &str,
    entries: &mut BTreeMap<String, Option<Vec<u8>>>,
    total: &mut u64,
) -> Result<(), DeployerError> {
    let mut children: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| io_err(dir.display(), e))?
        .collect::<Result<_, _>>()
        .map_err(|e| io_err(dir.display(), e))?;
    children.sort_by_key(|c| c.file_name());
    for child in children {
        let name = child
            .file_name()
            .into_string()
            .map_err(|n| io_err("a non-UTF-8 file name", format!("{n:?}")))?;
        let path = child.path();
        let ty = child.file_type().map_err(|e| io_err(path.display(), e))?;
        if ty.is_symlink() {
            return Err(DeployerError::Provider(format!(
                "ssh-host: the local store contains a symlink ({}); refusing to follow or ship it",
                path.display()
            )));
        }
        rel.push(name);
        let key = format!("{env_id}/{}", rel.join("/"));
        let verdict = classify(rel, ty.is_dir());
        match (verdict, ty.is_dir()) {
            (Verdict::Skip, _) => {}
            // Replaced files are added by the caller from in-memory sources.
            (Verdict::ReplaceEnvironment | Verdict::ReplaceDevStore, false) => {}
            (Verdict::PatchRuntime, false) => {
                let raw = std::fs::read(&path).map_err(|e| io_err(path.display(), e))?;
                *total += raw.len() as u64;
                entries.insert(key, Some(patch_runtime_json(&raw, input.params)?));
            }
            (_, true) => {
                entries.insert(key, None);
                walk(&path, rel, input, env_id, entries, total)?;
            }
            (_, false) => {
                let meta = child.metadata().map_err(|e| io_err(path.display(), e))?;
                *total += meta.len();
                if *total > MAX_SNAPSHOT_BYTES {
                    return Err(DeployerError::Provider(format!(
                        "ssh-host: the local store is larger than {} MiB; refusing to ship it",
                        MAX_SNAPSHOT_BYTES / (1024 * 1024)
                    )));
                }
                let bytes = std::fs::read(&path).map_err(|e| io_err(path.display(), e))?;
                entries.insert(key, Some(bytes));
            }
        }
        rel.pop();
    }
    Ok(())
}

/// Rewrite `listen_addr` to the address the unit binds. Left untouched when the
/// document has no string `listen_addr` (the unit's environment variables still
/// carry the bind address); refused when it is not JSON at all.
pub(crate) fn patch_runtime_json(
    raw: &[u8],
    params: &SshHostParams,
) -> Result<Vec<u8>, DeployerError> {
    let mut doc: Value = serde_json::from_slice(raw).map_err(|e| {
        DeployerError::Provider(format!(
            "ssh-host: the local store's runtime.json is not valid JSON: {e}"
        ))
    })?;
    if let Some(slot) = doc.get_mut("listen_addr").filter(|v| v.is_string()) {
        *slot = Value::String(format!("{}:{}", params.bind_addr(), params.listen_port));
        return serde_json::to_vec_pretty(&doc).map_err(|e| {
            DeployerError::Provider(format!("ssh-host: rewriting runtime.json: {e}"))
        });
    }
    Ok(raw.to_vec())
}

fn write_tar(entries: &BTreeMap<String, Option<Vec<u8>>>) -> Result<Vec<u8>, DeployerError> {
    let fail = |e: std::io::Error| {
        DeployerError::Provider(format!("ssh-host: building the store archive: {e}"))
    };
    let mut builder = tar::Builder::new(Vec::new());
    for (path, content) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        match content {
            None => {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_mode(0o700);
                header.set_size(0);
                header.set_cksum();
                builder
                    .append_data(&mut header, format!("{path}/"), std::io::empty())
                    .map_err(fail)?;
            }
            Some(bytes) => {
                header.set_entry_type(tar::EntryType::Regular);
                header.set_mode(0o600);
                header.set_size(bytes.len() as u64);
                header.set_cksum();
                builder
                    .append_data(&mut header, path, bytes.as_slice())
                    .map_err(fail)?;
            }
        }
    }
    builder.into_inner().map_err(fail)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Read;

    use serde_json::json;

    use super::*;
    use crate::env_packs::deployer::conformance::build_fixture_env;

    fn rel(p: &str) -> Vec<String> {
        p.split('/').map(str::to_string).collect()
    }

    fn params(extra: Value) -> SshHostParams {
        let mut a = json!({"host": "vm.example.com", "user": "greentic"});
        for (k, v) in extra.as_object().unwrap() {
            a[k] = v.clone();
        }
        SshHostParams::from_answers(&build_fixture_env(), &a).unwrap()
    }

    /// A store shaped like the spike's: everything the policy touches.
    pub(crate) fn fixture_store(dir: &Path) {
        let files: &[(&str, &str)] = &[
            ("conformance/environment.json", "{\"on\":\"disk\"}"),
            (
                "conformance/runtime.json",
                "{\"listen_addr\":\"127.0.0.1:8080\",\"x\":1}",
            ),
            ("conformance/.lock", ""),
            (
                "conformance/.greentic/dev/.dev.secrets.env",
                "RAW-UNFILTERED",
            ),
            ("conformance/.greentic/dev/.dev.secrets.env.lock", ""),
            (
                "conformance/.greentic/state/dev/.dev.secrets.env",
                "RAW-STATE-COPY",
            ),
            ("conformance/backups/b1.json", "{}"),
            ("conformance/audit/a.log", "x"),
            ("conformance/revisions/r1/bundle.gtbundle", "BIG"),
            ("conformance/revisions/r1/pack-list.lock", "locked"),
            ("conformance/revisions/r1/bundle.lock.json", "{}"),
            ("conformance/revisions/r1/bundle-lock.json", "{}"),
            ("conformance/revisions/r1/manifest.json", "{}"),
            (
                "conformance/revisions/r1/bundle/.greentic/dev/.dev.secrets.env",
                "BUNDLE-OWN",
            ),
            ("revision-signing.key", "RUNTIME-KEY"),
            ("logs/x.log", "log"),
            ("conformance/revision-signing.key", "LOCAL-ENV-KEY"),
            ("conformance/logs/y.log", "log"),
            ("other-env/environment.json", "{}"),
        ];
        for (path, content) in files {
            let full = dir.join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, content).unwrap();
        }
    }

    fn entries_of(archive: &StoreArchive) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let mut ar = tar::Archive::new(archive.bytes.as_slice());
        for e in ar.entries().unwrap() {
            let mut e = e.unwrap();
            let path = e.path().unwrap().to_string_lossy().into_owned();
            let mut content = Vec::new();
            e.read_to_end(&mut content).unwrap();
            out.push((path, content));
        }
        out
    }

    fn build(dir: &Path, dev: Option<&[u8]>, p: &SshHostParams) -> StoreArchive {
        let env = build_fixture_env();
        build_store_archive(&SnapshotInput {
            store_root: dir,
            revision_id: env.revisions[0].revision_id,
            env: &env,
            dev_secrets: dev,
            params: p,
        })
        .unwrap()
    }

    fn files(archive: &StoreArchive) -> Vec<String> {
        entries_of(archive)
            .into_iter()
            .map(|(p, _)| p)
            .filter(|p| !p.ends_with('/'))
            .collect()
    }

    #[test]
    fn the_policy_excludes_exact_names_and_positions_only() {
        use Verdict::*;
        assert_eq!(classify(&rel(".lock"), false), Skip);
        assert_eq!(
            classify(&rel(".greentic/dev/.dev.secrets.env.lock"), false),
            Skip
        );
        assert_eq!(classify(&rel("backups"), true), Skip);
        assert_eq!(classify(&rel("audit"), true), Skip);
        assert_eq!(classify(&rel("revisions/r1/bundle.gtbundle"), false), Skip);
        assert_eq!(
            classify(&rel(".greentic/dev/.dev.secrets.env"), false),
            ReplaceDevStore
        );
        assert_eq!(
            classify(&rel(".greentic/state/dev/.dev.secrets.env"), false),
            Skip
        );
        assert_eq!(
            classify(&rel("environment.json"), false),
            ReplaceEnvironment
        );
        assert_eq!(classify(&rel("runtime.json"), false), PatchRuntime);
        // The lookalikes that a glob would have eaten stay in.
        for kept in [
            "revisions/r1/pack-list.lock",
            "revisions/r1/bundle.lock.json",
            "revisions/r1/bundle-lock.json",
            "pack-list.lock",
            "revisions/r1/bundle/.greentic/dev/.dev.secrets.env",
            "revisions/r1/bundle.gtbundle.sig",
            "revisions/r1/x/bundle.gtbundle",
            "notbackups",
            "x/backups",
        ] {
            assert_eq!(classify(&rel(kept), false), Include, "{kept}");
        }
    }

    #[test]
    fn snapshot_ships_exactly_the_portable_set() {
        let dir = tempfile::tempdir().unwrap();
        fixture_store(dir.path());
        let archive = build(dir.path(), Some(b"FILTERED"), &params(json!({})));
        assert_eq!(
            files(&archive),
            vec![
                ".greentic-store.sha256",
                "conformance/.greentic/dev/.dev.secrets.env",
                "conformance/environment.json",
                "conformance/revisions/r1/bundle-lock.json",
                "conformance/revisions/r1/bundle.lock.json",
                "conformance/revisions/r1/bundle/.greentic/dev/.dev.secrets.env",
                "conformance/revisions/r1/manifest.json",
                "conformance/revisions/r1/pack-list.lock",
                "conformance/runtime.json",
            ]
        );
    }

    #[test]
    fn the_dev_store_is_the_injected_bytes_never_the_file_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        fixture_store(dir.path());
        let archive = build(dir.path(), Some(b"FILTERED"), &params(json!({})));
        let all = entries_of(&archive);
        let get = |p: &str| all.iter().find(|(k, _)| k == p).map(|(_, v)| v.clone());
        assert_eq!(
            get("conformance/.greentic/dev/.dev.secrets.env").unwrap(),
            b"FILTERED"
        );
        for (_, content) in &all {
            let text = String::from_utf8_lossy(content);
            assert!(!text.contains("RAW-UNFILTERED") && !text.contains("RAW-STATE-COPY"));
        }
        // The bundle's own dev-store is the bundle's, and travels.
        assert_eq!(
            get("conformance/revisions/r1/bundle/.greentic/dev/.dev.secrets.env").unwrap(),
            b"BUNDLE-OWN"
        );
    }

    #[test]
    fn without_injected_secrets_no_dev_store_is_shipped_at_all() {
        let dir = tempfile::tempdir().unwrap();
        fixture_store(dir.path());
        let archive = build(dir.path(), None, &params(json!({})));
        let shipped = files(&archive);
        assert!(
            !shipped
                .iter()
                .any(|p| p == "conformance/.greentic/dev/.dev.secrets.env")
        );
        assert!(!shipped.iter().any(|p| p.contains("state/dev")));
    }

    #[test]
    fn runtime_and_other_envs_state_never_ship() {
        let dir = tempfile::tempdir().unwrap();
        fixture_store(dir.path());
        let archive = build(dir.path(), None, &params(json!({})));
        let shipped = files(&archive).join("\n");
        for never in [
            "revision-signing.key",
            "logs/",
            "other-env",
            "backups",
            "audit",
            "bundle.gtbundle",
            "/.lock\n",
        ] {
            assert!(!shipped.contains(never), "{never} shipped:\n{shipped}");
        }
    }

    #[test]
    fn environment_json_is_the_seed_form_not_the_disk_file() {
        let dir = tempfile::tempdir().unwrap();
        fixture_store(dir.path());
        let archive = build(dir.path(), None, &params(json!({})));
        let env_json = entries_of(&archive)
            .into_iter()
            .find(|(p, _)| p == "conformance/environment.json")
            .unwrap()
            .1;
        let parsed: Value = serde_json::from_slice(&env_json).unwrap();
        assert_eq!(parsed["environment_id"], "conformance");
    }

    #[test]
    fn runtime_json_listen_addr_follows_the_bind_settings() {
        let raw = br#"{"listen_addr":"127.0.0.1:8080","keep":true}"#;
        let loop_back = patch_runtime_json(raw, &params(json!({"listen_port": 9000}))).unwrap();
        let v: Value = serde_json::from_slice(&loop_back).unwrap();
        assert_eq!(v["listen_addr"], "127.0.0.1:9000");
        assert_eq!(v["keep"], true);
        let open = patch_runtime_json(raw, &params(json!({"expose": true}))).unwrap();
        let v: Value = serde_json::from_slice(&open).unwrap();
        assert_eq!(v["listen_addr"], "0.0.0.0:8080");
        // No listen_addr: untouched. Not JSON: refused.
        assert_eq!(
            patch_runtime_json(b"{\"a\":1}", &params(json!({}))).unwrap(),
            b"{\"a\":1}"
        );
        assert!(patch_runtime_json(b"nope", &params(json!({}))).is_err());
    }

    #[test]
    fn archive_is_deterministic_and_the_marker_names_the_content_hash() {
        let dir = tempfile::tempdir().unwrap();
        fixture_store(dir.path());
        let p = params(json!({}));
        let a = build(dir.path(), Some(b"x"), &p);
        let b = build(dir.path(), Some(b"x"), &p);
        assert_eq!(a, b);
        let marker = entries_of(&a)
            .into_iter()
            .find(|(p, _)| p == STORE_MARKER_FILE)
            .unwrap()
            .1;
        assert_eq!(
            String::from_utf8(marker).unwrap(),
            format!("{}\n", a.content_sha256)
        );
        assert_ne!(
            a.content_sha256,
            build(dir.path(), Some(b"y"), &p).content_sha256
        );
        assert_ne!(
            a.content_sha256,
            build(dir.path(), Some(b"x"), &params(json!({"expose": true}))).content_sha256
        );
    }

    #[test]
    fn a_missing_env_dir_or_a_symlink_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let env = build_fixture_env();
        let input = |root: &Path, p: &SshHostParams| {
            build_store_archive(&SnapshotInput {
                store_root: root,
                revision_id: env.revisions[0].revision_id,
                env: &env,
                dev_secrets: None,
                params: p,
            })
        };
        let p = params(json!({}));
        let err = input(dir.path(), &p).unwrap_err().to_string();
        assert!(err.contains("op env init"), "{err}");

        fixture_store(dir.path());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/passwd", dir.path().join("conformance/evil")).unwrap();
            let err = input(dir.path(), &p).unwrap_err().to_string();
            assert!(err.contains("symlink"), "{err}");
        }
    }
}
