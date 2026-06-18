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

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use greentic_deploy_spec::{EnvId, LockedPack, PackId, PackListLock, RevisionId, SchemaVersion};
use sha2::{Digest, Sha256};

use crate::environment::LocalFsStore;
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

/// Materialize, on disk, everything the bundle-less `greentic-start --env` boot
/// needs to **serve** an already-staged revision, from a locally-available
/// `.gtbundle`.
///
/// A remote worker (e.g. a K8s pod) receives the env's `environment.json` — the
/// staged [`Revision`] with its `bundle_source_uri` + `bundle_digest` — but not
/// the multi-MB pack bytes (a ConfigMap can't carry them). It pulls the
/// `.gtbundle` at boot and calls this to lay down the artifacts the boot loader
/// file-checks (`pack-list.lock`, `pack-config.v1` docs) and the runner host
/// digest-verifies (the `.gtpack` files), then (re)writes `runtime-config.json`
/// so the next `load_or_empty` activates the revision instead of falling back
/// to a probes-only boot.
///
/// Runs under the env flock ([`LocalFsStore::transact`]). Steps:
/// 1. extract + pin packs ([`stage_local_bundle`]) → `pack-list.lock` + `.gtpack`s,
/// 2. **integrity gate** — the staged bundle's content digest MUST equal the
///    revision's recorded `bundle_digest`; a mismatch means the pull served
///    different bytes than the deployer pinned, so the extraction is dropped and
///    an [`OpError::Conflict`] is returned (fail-closed),
/// 3. materialize `pack-config.v1` docs ([`super::pack_config_stage::materialize_pack_configs`]),
/// 4. project + write `runtime-config.json` ([`Locked::refresh_runtime_config`]).
///
/// Idempotent: a re-run replaces the per-revision extraction. The revision must
/// already exist in the env (staged by the deployer); this re-materializes its
/// on-disk artifacts from the bundle, it does not create or mutate the revision
/// record.
///
/// [`Revision`]: greentic_deploy_spec::Revision
/// [`Locked::refresh_runtime_config`]: crate::environment::store::Locked::refresh_runtime_config
pub fn materialize_revision_from_bundle(
    store: &LocalFsStore,
    env_id: &EnvId,
    revision_id: RevisionId,
    bundle_path: &Path,
) -> Result<(), OpError> {
    store.transact(env_id, |locked| {
        let env = locked.load()?;
        let revision = env
            .revisions
            .iter()
            .find(|r| r.revision_id == revision_id)
            .ok_or_else(|| {
                OpError::NotFound(format!("revision `{revision_id}` not found in env `{env_id}`"))
            })?;
        let bundle_id = env
            .bundles
            .iter()
            .find(|b| b.deployment_id == revision.deployment_id)
            .map(|b| b.bundle_id.clone())
            .ok_or_else(|| {
                OpError::NotFound(format!(
                    "deployment `{}` for revision `{revision_id}` has no bundle in env `{env_id}`",
                    revision.deployment_id
                ))
            })?;

        let env_dir = store.env_dir(env_id)?;
        let rev_dir = env_dir.join("revisions").join(revision_id.to_string());
        let drop_rev_dir = || {
            let _ = std::fs::remove_dir_all(&rev_dir);
        };

        // 1. Extract + pin packs under `<env_dir>/revisions/<rev>/`.
        let staged = stage_local_bundle(&env_dir, revision_id, bundle_path)?;

        // 2. Integrity gate: the bytes the worker pulled MUST match what the
        //    deployer pinned on the revision. `stage_local_bundle` binds the
        //    digest to the immutable staged copy, so this compares like for
        //    like. Fail closed — a mismatch is a supply-chain signal, not a
        //    recoverable condition.
        if staged.bundle_digest != revision.bundle_digest {
            drop_rev_dir();
            return Err(OpError::Conflict(format!(
                "pulled bundle digest `{}` does not match revision `{revision_id}`'s pinned \
                 `{}`; refusing to serve unpinned bytes",
                staged.bundle_digest, revision.bundle_digest
            )));
        }
        // The lock ref is a pure function of the revision id, so re-staging the
        // same revision must reproduce the ref the revision already records. A
        // divergence means the two stage paths drifted — guard against it.
        if staged.pack_list_lock_ref != revision.pack_list_lock_ref {
            drop_rev_dir();
            return Err(OpError::Conflict(format!(
                "materialized pack-list lock ref `{}` diverges from revision `{revision_id}`'s `{}`",
                staged.pack_list_lock_ref.display(),
                revision.pack_list_lock_ref.display()
            )));
        }

        // 3. Materialize pack-config docs from the extracted bundle inputs. The
        //    refs are deterministic for a given (revision id, bundle), so they
        //    line up with what the revision already records — re-derive the
        //    files rather than trust the (absent) on-disk copies.
        let pinned_pack_ids: HashSet<String> = staged
            .lock
            .packs
            .iter()
            .map(|p| p.pack_id.as_str().to_string())
            .collect();
        super::pack_config_stage::materialize_pack_configs(
            &env_dir,
            &rev_dir,
            revision_id,
            env_id,
            &bundle_id,
            &pinned_pack_ids,
        )
        .inspect_err(|_| drop_rev_dir())?;

        // 4. (Re)write `runtime-config.json` so the next boot activates this
        //    revision. Projects from the env's traffic splits; if no split
        //    routes the revision yet, the file is removed and the worker serves
        //    probes-only until traffic lands (B0 rejects an empty config).
        locked.refresh_runtime_config(&env)?;
        Ok(())
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

#[cfg(test)]
mod materialize_tests {
    use super::*;
    use crate::cli::tests_common::{
        make_bundle_deployment, make_env, make_revision, make_traffic_split,
    };
    use crate::environment::mint_revision_id;
    use crate::environment::store::EnvironmentStore;
    use greentic_deploy_spec::{PackListEntry, RevisionLifecycle};
    use tempfile::tempdir;

    fn fixture_bundle() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/bundles/perf-smoke-bundle.gtbundle")
    }

    /// Build an env with a deployment and a revision staged from the fixture
    /// bundle (the deployer side), so `environment.json` records the real digest
    /// and lock ref a remote worker would receive, then return the ids and env
    /// dir. When `route` is set, a 100% traffic split points at the revision so
    /// `runtime-config.json` is materializable.
    fn seed_staged_env(store: &LocalFsStore, route: bool) -> (EnvId, RevisionId, PathBuf) {
        let env_id = EnvId::try_from("local").unwrap();
        let mut env = make_env("local");
        let deployment = make_bundle_deployment("local", "fast2flow");
        let did = deployment.deployment_id;
        env.bundles.push(deployment);

        let revision_id = mint_revision_id();
        let env_dir = store.env_dir(&env_id).unwrap();
        let staged = stage_local_bundle(&env_dir, revision_id, &fixture_bundle()).unwrap();

        let mut revision = make_revision("local", "fast2flow", &did, 1, RevisionLifecycle::Ready);
        revision.revision_id = revision_id;
        revision.bundle_digest = staged.bundle_digest.clone();
        revision.pack_list_lock_ref = staged.pack_list_lock_ref.clone();
        revision.bundle_source_uri =
            Some("oci://example.test/bundles/fast2flow@sha256:abc".to_string());
        revision.pack_list = staged
            .lock
            .packs
            .iter()
            .map(|p| PackListEntry::from_lock_primitives(p.pack_id.clone(), p.digest.clone()))
            .collect();
        env.revisions.push(revision);
        if route {
            env.traffic_splits.push(make_traffic_split(
                "local",
                "fast2flow",
                &did,
                &revision_id,
                "k1",
            ));
        }
        store.save(&env).unwrap();
        (env_id, revision_id, env_dir)
    }

    /// Happy path: a worker with only `environment.json` (pack bytes wiped)
    /// re-materializes the revision from the pulled bundle — `pack-list.lock`,
    /// the `.gtpack` files, and `runtime-config.json` all reappear, and the pack
    /// digests still match the lock.
    #[test]
    fn materializes_packs_lock_and_runtime_config_from_bundle() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (env_id, revision_id, env_dir) = seed_staged_env(&store, true);
        let rev_dir = env_dir.join("revisions").join(revision_id.to_string());

        // Simulate the worker: only environment.json shipped — wipe the staged
        // pack bytes + any runtime-config the deployer side may have written.
        std::fs::remove_dir_all(&rev_dir).unwrap();
        let runtime_config = env_dir.join("runtime-config.json");
        let _ = std::fs::remove_file(&runtime_config);
        assert!(!rev_dir.exists());

        materialize_revision_from_bundle(&store, &env_id, revision_id, &fixture_bundle()).unwrap();

        let lock_path = rev_dir.join("pack-list.lock");
        assert!(lock_path.is_file(), "pack-list.lock must be restored");
        let lock: PackListLock =
            serde_json::from_slice(&std::fs::read(&lock_path).unwrap()).unwrap();
        assert_eq!(lock.revision_id, revision_id);
        assert!(!lock.packs.is_empty(), "fixture bundle has a .gtpack");
        for pack in &lock.packs {
            let pack_path = env_dir.join(&pack.path);
            assert!(
                pack_path.is_file(),
                "extracted pack must exist: {}",
                pack_path.display()
            );
            assert_eq!(
                pack.digest,
                sha256_file(&pack_path).unwrap(),
                "pack digest must match the lock"
            );
        }
        assert!(
            runtime_config.is_file(),
            "runtime-config.json must be written when a split routes the revision"
        );
    }

    /// Integrity gate: when the pulled bundle's digest does not match the
    /// revision's pinned `bundle_digest`, the call fails closed and leaves no
    /// partial extraction behind.
    #[test]
    fn rejects_bundle_whose_digest_does_not_match_the_pin() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (env_id, revision_id, env_dir) = seed_staged_env(&store, true);
        let rev_dir = env_dir.join("revisions").join(revision_id.to_string());

        // Repin the revision to a digest the real fixture cannot reproduce.
        store
            .transact(&env_id, |locked| {
                let mut env = locked.load()?;
                let r = env
                    .revisions
                    .iter_mut()
                    .find(|r| r.revision_id == revision_id)
                    .unwrap();
                r.bundle_digest =
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string();
                locked.save(&env)
            })
            .unwrap();
        std::fs::remove_dir_all(&rev_dir).unwrap();

        let err = materialize_revision_from_bundle(&store, &env_id, revision_id, &fixture_bundle())
            .unwrap_err();
        assert!(
            matches!(err, OpError::Conflict(_)),
            "digest mismatch must be a Conflict, got: {err}"
        );
        assert!(format!("{err}").contains("does not match"));
        assert!(
            !rev_dir.exists(),
            "a rejected materialization must not leave a partial extraction"
        );
    }

    /// A revision id absent from the env is a NotFound, not a panic.
    #[test]
    fn missing_revision_is_not_found() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (env_id, _rid, _env_dir) = seed_staged_env(&store, false);
        let bogus = mint_revision_id();
        let err = materialize_revision_from_bundle(&store, &env_id, bogus, &fixture_bundle())
            .unwrap_err();
        assert!(matches!(err, OpError::NotFound(_)), "got: {err}");
    }
}
