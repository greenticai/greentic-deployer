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
    let rev_dir = env_dir.join("revisions").join(revision_id.to_string());
    // No Revision is recorded for a failed stage (the caller's transact rolls
    // back env.json), so a partial copy/extraction under this freshly-minted
    // rev dir would be an invisible orphan. Drop the whole rev dir on any error.
    stage_into(env_dir, &rev_dir, revision_id, bundle_path).inspect_err(|_| {
        let _ = std::fs::remove_dir_all(&rev_dir);
    })
}

fn stage_into(
    env_dir: &Path,
    rev_dir: &Path,
    revision_id: RevisionId,
    bundle_path: &Path,
) -> Result<StagedBundle, OpError> {
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

    // Bind the digest to the exact bytes we extract: copy the input into the
    // revision dir first, then hash AND unpack that immutable staged copy.
    // Hashing the caller's path and separately re-opening it for extraction
    // would let a swap between the two operations record one artifact's digest
    // while pinning another's packs. The staged copy lives under the env flock
    // (held by the caller) at a freshly-minted revision path, so nothing
    // rewrites it out from under us.
    let staged_bundle = rev_dir.join("bundle.gtbundle");
    std::fs::copy(bundle_path, &staged_bundle).map_err(|source| OpError::Io {
        path: staged_bundle.clone(),
        source,
    })?;
    let bundle_digest = sha256_file(&staged_bundle).map_err(|source| OpError::Io {
        path: staged_bundle.clone(),
        source,
    })?;

    // Hardened SquashFS unpack of the staged copy (path-traversal +
    // symlink-escape guards live in greentic-bundle, not duplicated here).
    greentic_bundle::build::unbundle_artifact(&staged_bundle, &extract_dir).map_err(|err| {
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

    // Pin the embedded `.gtpack`s. Scope the scan to the canonical `packs/`
    // subtree so a stray `.gtpack` elsewhere in the bundle (e.g. under
    // `resolved/`) can't silently join the runtime pack set. Each pack's
    // load-time identity is its content digest + path, re-verified by the
    // runner host; cross-checking the embedded pack manifest's id/version
    // against the bundle lock is deferred (needs a `.gtpack` reader) and is
    // belt-and-suspenders on top of the digest binding + bundle-level DSSE.
    let packs_dir = extract_dir.join("packs");
    if !packs_dir.is_dir() {
        return Err(OpError::InvalidArgument(format!(
            "bundle `{}` has no packs/ directory",
            bundle_path.display()
        )));
    }
    let mut gtpacks = Vec::new();
    collect_gtpacks(&packs_dir, &mut gtpacks).map_err(|source| OpError::Io {
        path: packs_dir.clone(),
        source,
    })?;
    if gtpacks.is_empty() {
        return Err(OpError::InvalidArgument(format!(
            "bundle `{}` contains no .gtpack artifacts under packs/",
            bundle_path.display()
        )));
    }

    let mut packs = Vec::with_capacity(gtpacks.len());
    for path in gtpacks {
        let digest = sha256_file(&path).map_err(|source| OpError::Io {
            path: path.clone(),
            source,
        })?;
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

/// Streaming SHA-256 of a file, returned as `sha256:<lowercase-hex>`. Streams
/// through a fixed buffer rather than loading the whole artifact into memory,
/// so a large bundle or pack can't blow up peak RSS. Shared with
/// `cli::env_apply` (manifest-vs-live digest diffing).
pub(crate) fn sha256_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// `collect_gtpacks` recurses into nested dirs and only matches `.gtpack`,
    /// ignoring other files. `stage_local_bundle` hands it the `packs/` subtree,
    /// so a `.gtpack` placed outside `packs/` is never pinned.
    #[test]
    fn collect_gtpacks_recurses_and_filters_by_extension() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        // Canonical layout under packs/.
        let dist = root.join("packs/alpha/dist");
        std::fs::create_dir_all(&dist).unwrap();
        std::fs::write(dist.join("alpha.gtpack"), b"PK\x03\x04").unwrap();
        std::fs::write(dist.join("readme.txt"), b"not a pack").unwrap();

        // A stray .gtpack OUTSIDE packs/ — must be excluded when we scan packs/.
        std::fs::write(root.join("stray.gtpack"), b"PK\x03\x04").unwrap();

        let mut found = Vec::new();
        collect_gtpacks(&root.join("packs"), &mut found).unwrap();

        assert_eq!(found.len(), 1, "only the packs/ .gtpack, got {found:?}");
        assert!(found[0].ends_with("alpha/dist/alpha.gtpack"));
    }
}
