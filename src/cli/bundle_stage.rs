//! Local `.gtbundle` staging into an env's revision directory. Two callers:
//! the deployer's `op revisions stage --bundle` ([`stage_local_bundle`]), and a
//! remote worker re-materializing an already-staged revision at boot
//! ([`materialize_revision_from_bundle`]).
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

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use greentic_deploy_spec::{
    BundleId, EnvId, LockedPack, PackId, PackListLock, Revision, RevisionId, SchemaVersion,
};
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
                OpError::NotFound(format!(
                    "revision `{revision_id}` not found in env `{env_id}`"
                ))
            })?;
        let bundle_id = env
            .bundles
            .iter()
            .find(|b| b.deployment_id == revision.deployment_id)
            .map(|b| &b.bundle_id)
            .ok_or_else(|| {
                OpError::NotFound(format!(
                    "deployment `{}` for revision `{revision_id}` has no bundle in env `{env_id}`",
                    revision.deployment_id
                ))
            })?;

        let env_dir = store.env_dir(env_id)?;
        let rev_dir = env_dir.join("revisions").join(revision_id.to_string());

        // Move any existing extraction aside BEFORE re-staging, so a failed
        // (re)materialization — a corrupt/wrong pull, a digest or lock-ref
        // mismatch, a pack-config rejection, or a transient unpack error inside
        // `stage_local_bundle` (which clears its own extract dir up front) —
        // rolls back to the prior good state instead of bricking a revision the
        // env still routes traffic to. The whole op holds the env flock, so the
        // move/restore can't race another writer.
        let backup_dir = env_dir.join("revisions").join(format!("{revision_id}.bak"));
        let _ = std::fs::remove_dir_all(&backup_dir); // clear a stale backup from an interrupted run
        let had_existing = rev_dir.exists();
        if had_existing {
            std::fs::rename(&rev_dir, &backup_dir).map_err(|source| OpError::Io {
                path: rev_dir.clone(),
                source,
            })?;
        }

        // Materialize into the now-empty `rev_dir`, then project runtime-config.
        // Any error rolls back; only an all-green run is promoted.
        let outcome =
            materialize_into_rev_dir(&env_dir, &rev_dir, env_id, bundle_id, bundle_path, revision)
                .and_then(|()| locked.refresh_runtime_config(&env).map_err(OpError::from));

        match outcome {
            Ok(()) => {
                // Promote: the fresh extraction passed every check; drop the
                // saved copy.
                let _ = std::fs::remove_dir_all(&backup_dir);
                Ok(())
            }
            Err(err) => {
                // Roll back: discard the partial new attempt and restore the
                // prior good extraction so the worker can still serve.
                let _ = std::fs::remove_dir_all(&rev_dir);
                if had_existing {
                    let _ = std::fs::rename(&backup_dir, &rev_dir);
                }
                Err(err)
            }
        }
    })
}

/// Steps 1–3 of [`materialize_revision_from_bundle`], writing only under
/// `rev_dir`: extract + pin packs, integrity-gate the staged bundle's digest
/// and lock ref against what `revision` recorded, then materialize the
/// pack-config docs. The caller owns the move-aside/rollback that keeps a prior
/// good extraction recoverable when any step here fails.
fn materialize_into_rev_dir(
    env_dir: &Path,
    rev_dir: &Path,
    env_id: &EnvId,
    bundle_id: &BundleId,
    bundle_path: &Path,
    revision: &Revision,
) -> Result<(), OpError> {
    let revision_id = revision.revision_id;

    // 1. Extract + pin packs under `<env_dir>/revisions/<rev>/`.
    let staged = stage_local_bundle(env_dir, revision_id, bundle_path)?;

    // 2. Integrity gate: the bytes the worker pulled MUST match what the deployer
    //    pinned on the revision. `stage_local_bundle` binds the digest to the
    //    immutable staged copy, so this compares like for like. Fail closed — a
    //    mismatch is a supply-chain signal, not a recoverable condition.
    if staged.bundle_digest != revision.bundle_digest {
        return Err(OpError::Conflict(format!(
            "pulled bundle digest `{}` does not match revision `{revision_id}`'s pinned `{}`; \
             refusing to serve unpinned bytes",
            staged.bundle_digest, revision.bundle_digest
        )));
    }
    // The lock ref is a pure function of the revision id, so re-staging the same
    // revision must reproduce the ref the revision already records. A divergence
    // means the two stage paths drifted — guard against it.
    if staged.pack_list_lock_ref != revision.pack_list_lock_ref {
        return Err(OpError::Conflict(format!(
            "materialized pack-list lock ref `{}` diverges from revision `{revision_id}`'s `{}`",
            staged.pack_list_lock_ref.display(),
            revision.pack_list_lock_ref.display()
        )));
    }

    // 3. Materialize pack-config docs from the extracted bundle inputs. The refs
    //    are deterministic for a given (revision id, bundle), so they line up
    //    with what the revision already records — re-derive the files rather than
    //    trust the (absent) on-disk copies.
    let pinned_pack_ids: HashSet<String> = staged
        .lock
        .packs
        .iter()
        .map(|p| p.pack_id.as_str().to_string())
        .collect();
    super::pack_config_stage::materialize_pack_configs(
        env_dir,
        rev_dir,
        revision_id,
        env_id,
        bundle_id,
        &pinned_pack_ids,
    )?;
    Ok(())
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

    // Pin the embedded `.gtpack`s from the bundle's TWO canonical runtime pack
    // roots. `gtbundle-v1` splits them: `app_packs` are staged under `packs/`,
    // `extension_providers` under `providers/<domain>/` (see the bundle's own
    // `bundle-manifest.json`). Scanning only `packs/` is what left every
    // bundle-shipped provider — the webchat GUI included — invisible to the
    // revision runtime: its packs never entered `pack-list.lock`, so
    // `revision_boot` never handed them to route discovery and every
    // provider-declared route 405'd.
    //
    // The scan stays SCOPED (it is not a whole-tree glob): a stray `.gtpack`
    // under `resolved/`, `.cache/` or the bundle root still cannot join the
    // runtime pack set. That scoping was deliberate security hardening and is
    // preserved — `providers/` is a declared pack root, not a stray location.
    //
    // Each pack's load-time identity is its content digest + path, re-verified
    // by the runner host; cross-checking the embedded pack manifest's id/version
    // against the bundle lock is deferred (needs a `.gtpack` reader) and is
    // belt-and-suspenders on top of the digest binding + bundle-level DSSE.
    // Emptiness is judged on the COMBINED set. `packs/` is not individually
    // mandatory: `app_packs` and `extension_providers` are independent inputs to
    // the bundle producer, so a bundle whose runtime packs are all providers is
    // well-formed. Demanding `packs/` here would reject it for having the wrong
    // kind of pack, which is exactly the single-root assumption this fix removes.
    let mut gtpacks = Vec::new();
    let packs_dir = extract_dir.join("packs");
    if packs_dir.is_dir() {
        collect_gtpacks(&packs_dir, &mut gtpacks).map_err(|source| OpError::Io {
            path: packs_dir.clone(),
            source,
        })?;
    }
    collect_provider_gtpacks(&extract_dir, &mut gtpacks).map_err(|source| OpError::Io {
        path: extract_dir.join(PROVIDERS_DIR),
        source,
    })?;
    if gtpacks.is_empty() {
        return Err(OpError::InvalidArgument(format!(
            "bundle `{}` contains no .gtpack artifacts under packs/ or providers/<domain>/",
            bundle_path.display()
        )));
    }

    reject_duplicate_pack_ids(&gtpacks)?;

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

/// The bundle's second runtime pack root. `gtbundle-v1` stages every
/// `extension_providers` entry under `providers/<domain>/` (`messaging`,
/// `state`, `oauth`, …) rather than `packs/`.
const PROVIDERS_DIR: &str = "providers";

/// `providers/deployer/` holds deployment-time IaC packs (Terraform/AWS/GCP/
/// Azure), NOT runtime WASM components. `greentic-bundle` hides this directory
/// outright while warming a bundle
/// (`build/warmup.rs::temporarily_hide_deployer_packs`), which is the same
/// judgement: these must never enter the runtime pack set. Pinning them here
/// would hand the runner host archives it cannot load.
const NON_RUNTIME_PROVIDER_DOMAINS: &[&str] = &["deployer"];

/// Collect the runtime provider packs: every `.gtpack` under
/// `providers/<domain>/`, skipping non-runtime domains.
///
/// Deliberately enumerates domain directories rather than recursing from
/// `providers/` in one shot — the per-domain step is what makes the
/// `deployer` exclusion possible at all.
fn collect_provider_gtpacks(extract_dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let providers_dir = extract_dir.join(PROVIDERS_DIR);
    if !providers_dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(&providers_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let domain = entry.file_name();
        if domain
            .to_str()
            .is_some_and(|d| NON_RUNTIME_PROVIDER_DOMAINS.contains(&d))
        {
            continue;
        }
        collect_gtpacks(&entry.path(), out)?;
    }
    Ok(())
}

/// Does this revision's `pack-list.lock` pin every runtime pack its own staged
/// bundle actually carries?
///
/// A revision staged before `providers/<domain>/` was scanned has a lock that
/// pins only the `packs/` entries, so the runtime loads none of the bundle's
/// providers and every route they declare 404s/405s. Nothing else notices: the
/// lock file EXISTS and its packs all resolve, so the `pack_ref` classifier
/// (which only distinguishes Resolved / Missing / Invalid) calls the revision
/// healthy, and `env apply` sees an unchanged bundle digest and converges.
/// The env would stay silently broken forever.
///
/// So convergence asks the stronger question — not "is the lock readable?" but
/// "is it COMPLETE?" — and a short lock re-stages on the next apply.
///
/// Returns `true` when we cannot tell (no lock ref, unreadable lock, no staged
/// bundle on disk — e.g. a K8s worker that never staged locally). This check
/// exists to force a re-stage that heals, never to fail an env it does not
/// understand.
pub fn pack_list_is_complete(
    env_dir: &Path,
    revision_id: RevisionId,
    pack_list_lock_ref: &Path,
) -> bool {
    if pack_list_lock_ref.as_os_str().is_empty() {
        return true;
    }
    let Ok(bytes) = std::fs::read(env_dir.join(pack_list_lock_ref)) else {
        return true;
    };
    let Ok(lock) = serde_json::from_slice::<PackListLock>(&bytes) else {
        return true;
    };
    // A lock belonging to some other revision tells us nothing about this one.
    // Force a re-stage rather than trusting it — re-staging writes a correct lock.
    if lock.revision_id != revision_id {
        return false;
    }
    let extract_dir = env_dir
        .join("revisions")
        .join(revision_id.to_string())
        .join("bundle");
    if !extract_dir.is_dir() {
        return true; // nothing staged locally — not ours to judge.
    }

    let mut on_disk = Vec::new();
    let packs_dir = extract_dir.join("packs");
    if packs_dir.is_dir() && collect_gtpacks(&packs_dir, &mut on_disk).is_err() {
        return true;
    }
    if collect_provider_gtpacks(&extract_dir, &mut on_disk).is_err() {
        return true;
    }
    // Compare env-relative PATHS, not pack ids. A pack id is the file stem, so
    // `packs/dup.gtpack` + `providers/messaging/dup.gtpack` would let ONE locked
    // entry satisfy BOTH on-disk files and a short lock would read as complete —
    // the env would then never re-stage, and the duplicate-id guard that should
    // have rejected the bundle would never even run. Paths are exact.
    let locked: HashSet<&Path> = lock.packs.iter().map(|p| p.path.as_path()).collect();
    on_disk.iter().all(|p| {
        p.strip_prefix(env_dir)
            .is_ok_and(|rel| locked.contains(rel))
    })
}

/// `pack_id` is the file stem, so two packs with the same stem under different
/// roots (`packs/foo.gtpack` + `providers/messaging/foo.gtpack`) would write a
/// lock with a duplicate `pack_id`. Reject that HERE, while we can still name
/// both paths, rather than letting a bundle stage cleanly and fail later at
/// revision activation with no clue which files collided.
fn reject_duplicate_pack_ids(gtpacks: &[PathBuf]) -> Result<(), OpError> {
    let mut seen: BTreeMap<&str, &Path> = BTreeMap::new();
    for path in gtpacks {
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue; // the `pack_id` build below reports a missing stem.
        };
        if let Some(previous) = seen.insert(stem, path.as_path()) {
            return Err(OpError::InvalidArgument(format!(
                "bundle stages two packs with the same pack id `{stem}`: `{}` and `{}`. \
                 Pack ids come from the file stem and must be unique across `packs/` \
                 and `providers/<domain>/`; rename or remove one.",
                previous.display(),
                path.display()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// `collect_gtpacks` recurses into nested dirs and only matches `.gtpack`,
    /// ignoring other files. It scans whatever root it is handed;
    /// `stage_local_bundle` hands it `packs/` and each `providers/<domain>/`,
    /// so a `.gtpack` outside those roots is never pinned.
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

    /// Lay out a bundle the way `gtbundle-v1` actually stages one: `app_packs`
    /// under `packs/`, `extension_providers` under `providers/<domain>/`, and
    /// the deployment-time IaC packs under `providers/deployer/`.
    fn bundle_tree(root: &Path) {
        for (dir, pack) in [
            ("packs", "quickstart"),
            ("providers/messaging", "messaging-webchat-gui"),
            ("providers/messaging", "messaging-slack"),
            ("providers/state", "state-memory"),
            ("providers/deployer", "deployer-terraform"),
        ] {
            let d = root.join(dir);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join(format!("{pack}.gtpack")), b"PK\x03\x04").unwrap();
        }
        // Stray packs outside both runtime roots stay excluded.
        std::fs::create_dir_all(root.join("resolved")).unwrap();
        std::fs::write(root.join("resolved/stray.gtpack"), b"PK\x03\x04").unwrap();
        std::fs::write(root.join("root-stray.gtpack"), b"PK\x03\x04").unwrap();
    }

    fn stems(paths: &[PathBuf]) -> Vec<String> {
        let mut s: Vec<String> = paths
            .iter()
            .map(|p| p.file_stem().unwrap().to_str().unwrap().to_string())
            .collect();
        s.sort();
        s
    }

    /// Collect from BOTH runtime roots the way `stage_into` does. Five tests were
    /// repeating this pair; a third root must only ever be added in one place.
    fn collect_runtime_gtpacks(root: &Path) -> Vec<PathBuf> {
        let mut found = Vec::new();
        let packs_dir = root.join("packs");
        if packs_dir.is_dir() {
            collect_gtpacks(&packs_dir, &mut found).unwrap();
        }
        collect_provider_gtpacks(root, &mut found).unwrap();
        found
    }

    /// THE REGRESSION THIS FIX EXISTS FOR: a bundle-shipped provider pack must be
    /// pinned into `pack-list.lock`. Before this, `providers/**` was never scanned,
    /// so `messaging-webchat-gui` never reached the runtime and every route it
    /// declared (`/v1/web/webchat/{tenant}`, DirectLine, `/auth/config`) 405'd on
    /// the revision path.
    #[test]
    fn provider_packs_are_pinned_alongside_app_packs() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        bundle_tree(root);

        let found = collect_runtime_gtpacks(root);

        assert_eq!(
            stems(&found),
            vec![
                "messaging-slack",
                "messaging-webchat-gui",
                "quickstart",
                "state-memory",
            ],
            "app pack + every runtime provider pack, and nothing else"
        );
    }

    /// `providers/deployer/` is IaC, not runtime WASM. Pinning it would hand the
    /// runner host an archive it cannot load.
    #[test]
    fn deployer_provider_packs_are_not_pinned() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        bundle_tree(root);

        let mut found = Vec::new();
        collect_provider_gtpacks(root, &mut found).unwrap();

        assert!(
            !stems(&found).iter().any(|s| s == "deployer-terraform"),
            "providers/deployer/ must never enter the runtime pack set, got {found:?}"
        );
    }

    /// The scan stays scoped: widening it to `providers/` must NOT become a
    /// whole-tree glob. Stray packs elsewhere in the bundle stay out.
    #[test]
    fn stray_packs_outside_the_two_runtime_roots_are_not_pinned() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        bundle_tree(root);

        let found = collect_runtime_gtpacks(root);

        let s = stems(&found);
        assert!(!s.iter().any(|p| p == "stray"), "resolved/ pack leaked in");
        assert!(!s.iter().any(|p| p == "root-stray"), "root pack leaked in");
    }

    /// A bundle with no `providers/` at all (an app-only bundle) still stages.
    #[test]
    fn missing_providers_dir_is_not_an_error() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("packs")).unwrap();
        std::fs::write(root.join("packs/only.gtpack"), b"PK\x03\x04").unwrap();

        let mut found = Vec::new();
        collect_provider_gtpacks(root, &mut found).unwrap();
        assert!(found.is_empty());
    }

    /// `pack_id` is the file stem, so the same stem under both roots would write a
    /// lock with a duplicate id. Caught at stage time, naming both paths.
    #[test]
    fn duplicate_pack_id_across_roots_is_rejected() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("packs")).unwrap();
        std::fs::create_dir_all(root.join("providers/messaging")).unwrap();
        std::fs::write(root.join("packs/dup.gtpack"), b"PK\x03\x04").unwrap();
        std::fs::write(root.join("providers/messaging/dup.gtpack"), b"PK\x03\x04").unwrap();

        let found = collect_runtime_gtpacks(root);

        let err =
            reject_duplicate_pack_ids(&found).expect_err("duplicate pack id must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("dup"),
            "error must name the colliding id: {msg}"
        );
        assert!(
            msg.contains("packs/dup.gtpack") && msg.contains("providers/messaging/dup.gtpack"),
            "error must name BOTH colliding paths: {msg}"
        );
    }

    /// Distinct ids across the two roots are fine — the guard must not reject the
    /// normal case it was added to protect.
    #[test]
    fn distinct_pack_ids_across_roots_are_accepted() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        bundle_tree(root);

        let found = collect_runtime_gtpacks(root);

        reject_duplicate_pack_ids(&found).expect("distinct ids must be accepted");
    }

    /// THE CALL-SITE TEST. The three tests above exercise the collectors directly,
    /// so they all stay green if the `collect_provider_gtpacks` CALL is deleted
    /// from `stage_into` — they would prove nothing about the shipped behaviour.
    /// This one stages a REAL `.gtbundle` carrying the real `gtbundle-v1` layout
    /// (`packs/` + `providers/{messaging,state,deployer}/` + a stray under
    /// `resolved/`) and asserts on the `pack-list.lock` that staging actually
    /// WROTE. Deleting the call site fails HERE.
    #[test]
    fn stage_writes_provider_packs_into_the_pack_list_lock() {
        let dir = tempdir().unwrap();
        let env_dir = dir.path();
        let revision_id = RevisionId::new();
        let bundle = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/bundles/provider-packs-bundle.gtbundle");

        let staged = stage_local_bundle(env_dir, revision_id, &bundle).expect("stage");

        let lock_path = env_dir.join(&staged.pack_list_lock_ref);
        let lock: PackListLock =
            serde_json::from_slice(&std::fs::read(&lock_path).unwrap()).unwrap();

        let mut ids: Vec<String> = lock.packs.iter().map(|p| p.pack_id.to_string()).collect();
        ids.sort();
        assert_eq!(
            ids,
            vec!["app", "messaging-webchat-gui", "state-memory"],
            "the lock must pin the app pack AND every runtime provider pack — \
             pinning only `app` is the regression that made bundle-shipped \
             providers invisible to the revision runtime"
        );

        // Every pinned pack resolves to a real file whose digest matches the lock.
        for pack in &lock.packs {
            let p = env_dir.join(&pack.path);
            assert!(p.is_file(), "pinned pack must exist: {}", p.display());
            assert_eq!(pack.digest, sha256_file(&p).unwrap(), "digest must bind");
        }

        // The provider pack keeps its `providers/<domain>/` location — staging pins
        // it where the bundle put it, it does not relocate it.
        let webchat = lock
            .packs
            .iter()
            .find(|p| p.pack_id.to_string() == "messaging-webchat-gui")
            .expect("webchat pack pinned");
        assert!(
            webchat
                .path
                .to_string_lossy()
                .contains("providers/messaging/"),
            "expected the pack pinned under providers/messaging/, got {}",
            webchat.path.display()
        );
    }

    /// Stage the provider fixture and return `(revision_id, pack_list_lock_ref)`.
    fn staged_revision(env_dir: &Path) -> (RevisionId, PathBuf) {
        let revision_id = RevisionId::new();
        let bundle = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/bundles/provider-packs-bundle.gtbundle");
        let staged = stage_local_bundle(env_dir, revision_id, &bundle).expect("stage");
        (revision_id, staged.pack_list_lock_ref)
    }

    /// A freshly-staged revision pins everything its bundle carries.
    #[test]
    fn freshly_staged_revision_has_a_complete_pack_list() {
        let dir = tempdir().unwrap();
        let (rev, lock_ref) = staged_revision(dir.path());
        assert!(pack_list_is_complete(dir.path(), rev, &lock_ref));
    }

    /// THE MIGRATION CASE. Simulate a revision staged by the OLD deployer: the same
    /// bundle on disk (providers and all), but a lock pinning only the `packs/`
    /// entry. This MUST read as incomplete — that verdict is what makes `env apply`
    /// re-stage instead of converging on a silently-broken env.
    #[test]
    fn revision_staged_before_the_fix_has_an_incomplete_pack_list() {
        let dir = tempdir().unwrap();
        let env_dir = dir.path();
        let (rev, lock_ref) = staged_revision(env_dir);

        // Rewrite the lock the way the pre-fix deployer would have written it:
        // drop every provider pack, keep the app pack.
        let lock_path = env_dir.join(&lock_ref);
        let mut lock: PackListLock =
            serde_json::from_slice(&std::fs::read(&lock_path).unwrap()).unwrap();
        lock.packs.retain(|p| p.pack_id.to_string() == "app");
        assert_eq!(lock.packs.len(), 1, "pre-fix lock pins only the app pack");
        std::fs::write(&lock_path, serde_json::to_vec(&lock).unwrap()).unwrap();

        assert!(
            !pack_list_is_complete(env_dir, rev, &lock_ref),
            "a lock missing the bundle's provider packs must read as INCOMPLETE, \
             otherwise a pre-fix env converges and never heals"
        );
    }

    /// `providers/deployer/` is not a runtime pack, so its absence from the lock
    /// must NOT make a healthy revision look incomplete — that would re-stage the
    /// env on every apply, forever.
    #[test]
    fn omitting_the_deployer_pack_does_not_make_a_lock_look_incomplete() {
        let dir = tempdir().unwrap();
        let env_dir = dir.path();
        let (rev, lock_ref) = staged_revision(env_dir);

        let extract = env_dir
            .join("revisions")
            .join(rev.to_string())
            .join("bundle");
        assert!(
            extract
                .join("providers/deployer/deployer-terraform.gtpack")
                .is_file(),
            "fixture must actually ship a deployer pack or this test proves nothing"
        );
        assert!(pack_list_is_complete(env_dir, rev, &lock_ref));
    }

    /// A bundle whose runtime packs are ALL providers is well-formed: `app_packs`
    /// and `extension_providers` are independent inputs to the bundle producer.
    /// Requiring `packs/` would reject it for having the wrong KIND of pack —
    /// the single-root assumption this fix exists to remove.
    #[test]
    fn a_provider_only_bundle_stages() {
        let dir = tempdir().unwrap();
        let env_dir = dir.path();
        let revision_id = RevisionId::new();
        let bundle = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/bundles/provider-only-bundle.gtbundle");

        let staged = stage_local_bundle(env_dir, revision_id, &bundle)
            .expect("a bundle with only provider packs must stage");

        let lock: PackListLock = serde_json::from_slice(
            &std::fs::read(env_dir.join(&staged.pack_list_lock_ref)).unwrap(),
        )
        .unwrap();
        let ids: Vec<String> = lock.packs.iter().map(|p| p.pack_id.to_string()).collect();
        assert_eq!(ids, vec!["messaging-webchat-gui"]);
    }

    /// A bundle with NO runtime packs in EITHER root is still rejected — widening
    /// the scan must not turn "empty bundle" into a silent success.
    #[test]
    fn a_bundle_with_no_runtime_packs_in_either_root_is_rejected() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("extract");
        std::fs::create_dir_all(root.join("providers/deployer")).unwrap();
        std::fs::write(root.join("providers/deployer/iac.gtpack"), b"PK\x03\x04").unwrap();

        let mut found = Vec::new();
        collect_provider_gtpacks(&root, &mut found).unwrap();
        assert!(
            found.is_empty(),
            "only a deployer pack is present, so the runtime pack set is empty"
        );
    }

    /// Completeness compares env-relative PATHS, not pack ids. Pack ids are file
    /// stems, so with a stem-based comparison ONE locked `dup` entry would satisfy
    /// BOTH `packs/dup.gtpack` and `providers/messaging/dup.gtpack` — a short lock
    /// would read as complete, the env would never re-stage, and the duplicate-id
    /// guard that should have rejected the bundle would never even run.
    #[test]
    fn a_short_lock_is_incomplete_even_when_the_missing_pack_shares_a_file_stem() {
        let dir = tempdir().unwrap();
        let env_dir = dir.path();
        let revision_id = RevisionId::new();

        // Hand-build the staged state: staging itself would now reject this bundle,
        // so the only way to hold it is as a legacy revision already on disk.
        let rev_dir = env_dir.join("revisions").join(revision_id.to_string());
        let extract = rev_dir.join("bundle");
        std::fs::create_dir_all(extract.join("packs")).unwrap();
        std::fs::create_dir_all(extract.join("providers/messaging")).unwrap();
        std::fs::write(extract.join("packs/dup.gtpack"), b"PK\x03\x04a").unwrap();
        std::fs::write(
            extract.join("providers/messaging/dup.gtpack"),
            b"PK\x03\x04b",
        )
        .unwrap();

        // The pre-fix lock: only the packs/ entry, whose pack_id is also `dup`.
        let app = extract.join("packs/dup.gtpack");
        let lock = PackListLock {
            schema: SchemaVersion::new(SchemaVersion::PACK_LIST_LOCK_V1),
            revision_id,
            packs: vec![LockedPack {
                pack_id: PackId::new("dup"),
                path: app.strip_prefix(env_dir).unwrap().to_path_buf(),
                digest: sha256_file(&app).unwrap(),
            }],
        };
        let lock_ref = rev_dir.join("pack-list.lock");
        std::fs::write(&lock_ref, serde_json::to_vec(&lock).unwrap()).unwrap();
        let lock_ref = lock_ref.strip_prefix(env_dir).unwrap().to_path_buf();

        assert!(
            !pack_list_is_complete(env_dir, revision_id, &lock_ref),
            "the provider `dup` pack is NOT pinned — sharing a file stem with the \
             app pack must not disguise that"
        );
    }

    /// Unknowable cases are "complete": this check exists to trigger a heal, never
    /// to fail an env it cannot see (e.g. a K8s worker with no local staging).
    #[test]
    fn unstaged_or_unreadable_revisions_are_treated_as_complete() {
        let dir = tempdir().unwrap();
        let env_dir = dir.path();

        assert!(
            pack_list_is_complete(env_dir, RevisionId::new(), Path::new("")),
            "empty ref is the documented no-pinned-pack-list signal"
        );
        assert!(
            pack_list_is_complete(
                env_dir,
                RevisionId::new(),
                Path::new("revisions/nope/pack-list.lock")
            ),
            "no lock on disk"
        );
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

    /// Repin a revision's `bundle_digest` to a value the real fixture cannot
    /// reproduce (all-zero sha256), under the env flock, so the next
    /// materialization fails the integrity gate.
    fn repin_to_unmatchable_digest(store: &LocalFsStore, env_id: &EnvId, revision_id: RevisionId) {
        store
            .transact(env_id, |locked| {
                let mut env = locked.load()?;
                env.revisions
                    .iter_mut()
                    .find(|r| r.revision_id == revision_id)
                    .unwrap()
                    .bundle_digest =
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string();
                locked.save(&env)
            })
            .unwrap();
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
        repin_to_unmatchable_digest(&store, &env_id, revision_id);
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

    /// Failure atomicity: when a revision dir is already materialized and a
    /// second materialization fails the integrity gate (a bad re-pull), the
    /// prior good extraction must survive intact and no backup may leak — a
    /// transient bad pull must not brick a revision the env still routes to.
    #[test]
    fn preserves_existing_revision_dir_when_re_materialization_fails() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (env_id, revision_id, env_dir) = seed_staged_env(&store, true);
        let rev_dir = env_dir.join("revisions").join(revision_id.to_string());
        let lock_path = rev_dir.join("pack-list.lock");

        // The seed already materialized a good rev_dir; capture the lock bytes so
        // we can prove they survive a failed re-materialization.
        assert!(
            lock_path.is_file(),
            "seed must leave a materialized rev dir"
        );
        let good_lock = std::fs::read(&lock_path).unwrap();

        // Repin the revision to a digest the fixture cannot reproduce, so the
        // next materialize fails the integrity gate AFTER moving the good dir
        // aside.
        repin_to_unmatchable_digest(&store, &env_id, revision_id);

        let err = materialize_revision_from_bundle(&store, &env_id, revision_id, &fixture_bundle())
            .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got: {err}");

        // The prior good extraction survives intact, and the backup is cleaned up.
        assert!(
            lock_path.is_file(),
            "existing pack-list.lock must survive a failed re-materialize"
        );
        assert_eq!(
            std::fs::read(&lock_path).unwrap(),
            good_lock,
            "the restored lock must be byte-identical to the original"
        );
        assert!(
            !env_dir
                .join("revisions")
                .join(format!("{revision_id}.bak"))
                .exists(),
            "the rollback backup must not leak"
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
