//! Local `.gtbundle` resolution for `op revisions stage --bundle` (PR-2 of the
//! local-deployment train).
//!
//! Extracts a local `.gtbundle` under the env's revision directory, derives a
//! pinned pack list from the embedded `.gtpack` artifacts (sha256 over the
//! on-disk file, so it matches what the runner host re-verifies at load), and
//! writes the `pack-list.lock` document that the revision's `pack_list_lock_ref`
//! points at. The runtime-config materializer then surfaces that ref for
//! `greentic-start` to boot from.
//!
//! SquashFS extraction is delegated to `greentic-bundle`'s hardened
//! `unbundle_artifact` (path-traversal + symlink-escape guards), rather than
//! re-implementing the unpack here.

use std::path::{Path, PathBuf};

use greentic_deploy_spec::{LockedPack, PackId, PackListLock, RevisionId, SchemaVersion};
use sha2::{Digest, Sha256};

use crate::environment::atomic_write::atomic_write_json;

use super::OpError;

/// Refs produced by staging a local bundle, threaded onto the new [`Revision`].
///
/// [`Revision`]: greentic_deploy_spec::Revision
pub struct StagedBundle {
    /// `sha256:<hex>` of the `.gtbundle` archive.
    pub bundle_digest: String,
    /// Env-relative path to the written `pack-list.lock`.
    pub pack_list_lock_ref: PathBuf,
    /// The lock document (also written to disk), returned for the outcome view.
    pub lock: PackListLock,
}

/// Extract `bundle_path` under `<env_dir>/revisions/<rev>/bundle/`, pin every
/// embedded `.gtpack` into a `pack-list.lock`, and return the refs to record on
/// the revision. Idempotent: a re-stage of the same revision id replaces the
/// prior extraction.
///
/// Must be called with the env's flock held (it writes under `env_dir`).
pub fn stage_local_bundle(
    env_dir: &Path,
    revision_id: RevisionId,
    bundle_path: &Path,
) -> Result<StagedBundle, OpError> {
    if !bundle_path.is_file() {
        return Err(OpError::InvalidArgument(format!(
            "bundle `{}` is not a file",
            bundle_path.display()
        )));
    }

    // Digest the archive itself before unpacking it.
    let bundle_bytes = std::fs::read(bundle_path).map_err(|source| OpError::Io {
        path: bundle_path.to_path_buf(),
        source,
    })?;
    let bundle_digest = sha256_hex(&bundle_bytes);

    let rev_seg = revision_id.to_string();
    let rev_dir = env_dir.join("revisions").join(&rev_seg);
    let extract_dir = rev_dir.join("bundle");

    // Replace any partial/previous extraction so a re-stage is deterministic.
    if extract_dir.exists() {
        std::fs::remove_dir_all(&extract_dir).map_err(|source| OpError::Io {
            path: extract_dir.clone(),
            source,
        })?;
    }
    std::fs::create_dir_all(&extract_dir).map_err(|source| OpError::Io {
        path: extract_dir.clone(),
        source,
    })?;

    // Hardened SquashFS unpack (path-traversal + symlink-escape guards live in
    // greentic-bundle, not duplicated here).
    greentic_bundle::build::unbundle_artifact(bundle_path, &extract_dir).map_err(|err| {
        OpError::InvalidArgument(format!(
            "extract bundle `{}`: {err:#}",
            bundle_path.display()
        ))
    })?;

    // A `.gtbundle` always carries a bundle manifest; its absence means the
    // input was not a Greentic bundle.
    if !extract_dir.join("bundle-manifest.json").is_file() {
        return Err(OpError::InvalidArgument(format!(
            "`{}` is not a .gtbundle: extracted tree has no bundle-manifest.json",
            bundle_path.display()
        )));
    }

    // Pin every embedded `.gtpack` with its on-disk sha256.
    let mut gtpacks = Vec::new();
    collect_gtpacks(&extract_dir, &mut gtpacks).map_err(|source| OpError::Io {
        path: extract_dir.clone(),
        source,
    })?;
    if gtpacks.is_empty() {
        return Err(OpError::InvalidArgument(format!(
            "bundle `{}` contains no .gtpack artifacts",
            bundle_path.display()
        )));
    }

    let mut packs = Vec::with_capacity(gtpacks.len());
    for path in gtpacks {
        let bytes = std::fs::read(&path).map_err(|source| OpError::Io {
            path: path.clone(),
            source,
        })?;
        let digest = sha256_hex(&bytes);
        let rel = path
            .strip_prefix(env_dir)
            .map_err(|_| {
                OpError::InvalidArgument(format!(
                    "extracted pack `{}` escaped the env directory",
                    path.display()
                ))
            })?
            .to_path_buf();
        let pack_id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(PackId::new)
            .ok_or_else(|| {
                OpError::InvalidArgument(format!("pack `{}` has no file stem", path.display()))
            })?;
        packs.push(LockedPack {
            pack_id,
            path: rel,
            digest,
        });
    }
    // Stable, path-sorted order so the lock (and its digest) is deterministic.
    packs.sort_by(|a, b| a.path.cmp(&b.path));

    let lock = PackListLock {
        schema: SchemaVersion::new(SchemaVersion::PACK_LIST_LOCK_V1),
        revision_id,
        packs,
    };
    let lock_path = rev_dir.join("pack-list.lock");
    atomic_write_json(&lock_path, &lock)
        .map_err(|e| OpError::Store(crate::environment::store::StoreError::from(e)))?;
    let pack_list_lock_ref = lock_path
        .strip_prefix(env_dir)
        .map_err(|_| {
            OpError::InvalidArgument(format!(
                "pack-list.lock `{}` escaped the env directory",
                lock_path.display()
            ))
        })?
        .to_path_buf();

    Ok(StagedBundle {
        bundle_digest,
        pack_list_lock_ref,
        lock,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Recursively collect `*.gtpack` files under `dir`. Uses `file_type()` (which
/// does not follow symlinks), so a symlinked directory is skipped rather than
/// traversed — extraction has already rejected escaping symlinks, and we never
/// want to walk outside the extract tree.
fn collect_gtpacks(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_dir() {
            collect_gtpacks(&path, out)?;
        } else if file_type.is_file() && path.extension().and_then(|e| e.to_str()) == Some("gtpack")
        {
            out.push(path);
        }
    }
    Ok(())
}
