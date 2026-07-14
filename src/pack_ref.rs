//! Classification of a revision's env-relative pack refs (`pack_list_lock_ref`,
//! `pack_config_refs`) against the environment directory.
//!
//! ## Why this is not just "does the file exist"
//!
//! A ref that is well-formed, contained, and simply *absent* is a **stale
//! record**: environments staged before greentic 1.1.0 recorded a placeholder
//! `pack_list_lock_ref` of `pack-list.lock` for which no file was ever written.
//! The only code that writes that file — [`crate::cli::bundle_stage`]'s
//! `stage_local_bundle` — arrived *with* 1.1.0, and the legacy stage path
//! recorded whatever `pack_list_lock_ref` the caller passed, verbatim and
//! unvalidated. Nothing read the field back then, so the placeholder was inert
//! until `greentic-start` began dereferencing it at boot. Such a revision can
//! never serve, but it is a *migration* problem, not an attack.
//!
//! A ref that is absolute, escapes the env dir (lexically or through a
//! symlink), or names something that is not a regular file is **not** stale. It
//! is a containment violation, and every caller must keep failing closed on it.
//! Conflating the two would turn a path-traversal attempt into a "just skip it"
//! — so the lexical escape check runs BEFORE the filesystem is touched, and a
//! `../escape.lock` that happens not to exist is [`PackRefStatus::Invalid`],
//! never [`PackRefStatus::Missing`].

use std::path::{Component, Path, PathBuf};

use greentic_deploy_spec::{BundleId, DeploymentId, Environment, RevisionId};

use crate::path_safety::normalize_under_root;

/// The verdict on a single env-relative pack ref.
#[derive(Debug)]
pub enum PackRefStatus {
    /// Resolves to a regular file under the env dir. Carries the canonical
    /// absolute path.
    Resolved(PathBuf),
    /// Well-formed and contained, but names a file that does not exist. A
    /// revision staged before greentic 1.1.0 (see module docs). The deployment
    /// that owns it cannot serve and should be quarantined or repaired — but
    /// the env around it is fine.
    Missing {
        /// Where the ref pointed, for the operator-facing message.
        joined: PathBuf,
    },
    /// Absolute, escapes the env dir, or does not resolve to a regular file.
    /// Fail closed: this is never treated as a stale record.
    Invalid(anyhow::Error),
}

/// Classify `rel` — an env-relative pack ref taken from a `Revision` — against
/// `env_dir`. See [`PackRefStatus`] for how each verdict must be handled.
pub fn classify_pack_ref(env_dir: &Path, rel: &Path) -> PackRefStatus {
    // Lexical containment FIRST, before any filesystem access: a `..` ref that
    // does not exist must be Invalid, not Missing. `normalize_under_root`
    // cannot make this call for us — it canonicalizes, so a non-existent
    // `../escape.lock` fails as "cannot canonicalize", indistinguishable from
    // an absent-but-honest ref.
    if rel.as_os_str().is_empty() {
        return PackRefStatus::Invalid(anyhow::anyhow!("pack ref is empty"));
    }
    for component in rel.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return PackRefStatus::Invalid(anyhow::anyhow!(
                    "pack ref `{}` is not env-relative (absolute or escapes via `..`)",
                    rel.display()
                ));
            }
        }
    }

    let env_canon = match env_dir.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            return PackRefStatus::Invalid(anyhow::anyhow!(
                "failed to canonicalize env dir {}: {e}",
                env_dir.display()
            ));
        }
    };
    let joined = env_canon.join(rel);

    // `symlink_metadata` does not follow the final component, so a dangling
    // symlink reports as present here and is then rejected by
    // `normalize_under_root` below (it cannot canonicalize) — a broken symlink
    // is a containment question, not a stale record.
    match std::fs::symlink_metadata(&joined) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return PackRefStatus::Missing { joined };
        }
        Err(e) => {
            return PackRefStatus::Invalid(anyhow::anyhow!(
                "io error on {}: {e}",
                joined.display()
            ));
        }
        Ok(_) => {}
    }

    // It exists in some form. `normalize_under_root` is now the security gate:
    // it re-checks absoluteness and canonicalizes, so a symlink pointing out of
    // the env dir is caught here.
    match normalize_under_root(env_dir, rel) {
        Ok(canon) if canon.is_file() => PackRefStatus::Resolved(canon),
        Ok(canon) => PackRefStatus::Invalid(anyhow::anyhow!(
            "pack ref `{}` does not resolve to a file ({})",
            rel.display(),
            canon.display()
        )),
        Err(e) => PackRefStatus::Invalid(e),
    }
}

/// A revision that live traffic routes to, whose pinned pack list names a file
/// that does not exist — i.e. a [`PackRefStatus::Missing`] `pack_list_lock_ref`.
/// Such a revision cannot serve, and while it sits in a traffic split it takes
/// the whole environment's boot down with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleRevision {
    pub deployment_id: DeploymentId,
    pub revision_id: RevisionId,
    pub bundle_id: BundleId,
    /// The ref as recorded in `environment.json` (e.g. the bare `pack-list.lock`).
    pub recorded_ref: PathBuf,
    /// Where that ref resolves to — the file that does not exist.
    pub expected_path: PathBuf,
}

/// Scan the revisions that `env`'s traffic splits actually route to and report
/// those whose pinned pack list is missing from disk.
///
/// Scans `traffic_splits`, not `revisions`, for the same reason the
/// runtime-config materializer does: only a revision inside a split is
/// projected into the boot path, so only those can brick a boot. An archived
/// revision with a dead ref is inert and not worth reporting.
///
/// An EMPTY `pack_list_lock_ref` is skipped: that is the legitimate "no pinned
/// pack list" signal the materializer already fail-safes on, not a stale record.
pub fn scan_stale_revisions(env: &Environment, env_dir: &Path) -> Vec<StaleRevision> {
    let mut stale = Vec::new();
    for split in &env.traffic_splits {
        for entry in &split.entries {
            let Some(revision) = env.revisions.iter().find(|r| {
                r.revision_id == entry.revision_id && r.deployment_id == split.deployment_id
            }) else {
                continue;
            };
            if revision.pack_list_lock_ref.as_os_str().is_empty() {
                continue;
            }
            if let PackRefStatus::Missing { joined } =
                classify_pack_ref(env_dir, &revision.pack_list_lock_ref)
            {
                stale.push(StaleRevision {
                    deployment_id: split.deployment_id,
                    revision_id: entry.revision_id,
                    bundle_id: split.bundle_id.clone(),
                    recorded_ref: revision.pack_list_lock_ref.clone(),
                    expected_path: joined,
                });
            }
        }
    }
    stale
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn env_with_lock() -> TempDir {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("revisions/r1")).unwrap();
        fs::write(tmp.path().join("revisions/r1/pack-list.lock"), "{}").unwrap();
        tmp
    }

    #[test]
    fn resolves_a_real_env_relative_lock() {
        let tmp = env_with_lock();
        let status = classify_pack_ref(tmp.path(), Path::new("revisions/r1/pack-list.lock"));
        let PackRefStatus::Resolved(p) = status else {
            panic!("expected Resolved, got {status:?}");
        };
        assert!(p.is_file());
    }

    /// THE FIELD BUG: the pre-1.1.0 placeholder. Well-formed, contained, and
    /// pointing at a file no code ever wrote.
    #[test]
    fn bare_placeholder_is_missing_not_invalid() {
        let tmp = env_with_lock();
        let status = classify_pack_ref(tmp.path(), Path::new("pack-list.lock"));
        let PackRefStatus::Missing { joined } = status else {
            panic!("the pre-1.1.0 placeholder must classify as Missing, got {status:?}");
        };
        assert_eq!(
            joined,
            tmp.path().canonicalize().unwrap().join("pack-list.lock")
        );
    }

    /// A `..` escape that does NOT exist must fail closed, not be waved through
    /// as a stale record. This is the whole reason the lexical check runs first.
    #[test]
    fn nonexistent_parent_dir_escape_is_invalid_not_missing() {
        let tmp = env_with_lock();
        let status = classify_pack_ref(tmp.path(), Path::new("../nope.lock"));
        assert!(
            matches!(status, PackRefStatus::Invalid(_)),
            "a non-existent `..` escape must be Invalid, got {status:?}"
        );
    }

    /// The same escape when the target DOES exist — still invalid.
    #[test]
    fn existing_parent_dir_escape_is_invalid() {
        let tmp = TempDir::new().unwrap();
        let env_dir = tmp.path().join("env");
        fs::create_dir_all(&env_dir).unwrap();
        fs::write(tmp.path().join("secret.lock"), "secret").unwrap();
        let status = classify_pack_ref(&env_dir, Path::new("../secret.lock"));
        assert!(
            matches!(status, PackRefStatus::Invalid(_)),
            "expected Invalid, got {status:?}"
        );
    }

    #[test]
    fn absolute_ref_is_invalid() {
        let tmp = env_with_lock();
        let status = classify_pack_ref(tmp.path(), Path::new("/etc/passwd"));
        assert!(
            matches!(status, PackRefStatus::Invalid(_)),
            "expected Invalid, got {status:?}"
        );
    }

    /// A symlink that points outside the env dir must be caught by the
    /// canonicalizing gate, not classified as a healthy ref.
    #[cfg(unix)]
    #[test]
    fn symlink_escaping_the_env_dir_is_invalid() {
        let tmp = TempDir::new().unwrap();
        let env_dir = tmp.path().join("env");
        fs::create_dir_all(&env_dir).unwrap();
        fs::write(tmp.path().join("outside.lock"), "secret").unwrap();
        std::os::unix::fs::symlink(tmp.path().join("outside.lock"), env_dir.join("link.lock"))
            .unwrap();
        let status = classify_pack_ref(&env_dir, Path::new("link.lock"));
        assert!(
            matches!(status, PackRefStatus::Invalid(_)),
            "a symlink out of the env dir must be Invalid, got {status:?}"
        );
    }

    /// A dangling symlink exists (symlink_metadata succeeds) but cannot
    /// canonicalize — a containment question, not a stale record.
    #[cfg(unix)]
    #[test]
    fn dangling_symlink_is_invalid_not_missing() {
        let tmp = env_with_lock();
        std::os::unix::fs::symlink(
            tmp.path().join("does-not-exist"),
            tmp.path().join("dangling.lock"),
        )
        .unwrap();
        let status = classify_pack_ref(tmp.path(), Path::new("dangling.lock"));
        assert!(
            matches!(status, PackRefStatus::Invalid(_)),
            "expected Invalid, got {status:?}"
        );
    }

    #[test]
    fn directory_ref_is_invalid() {
        let tmp = env_with_lock();
        let status = classify_pack_ref(tmp.path(), Path::new("revisions/r1"));
        assert!(
            matches!(status, PackRefStatus::Invalid(_)),
            "expected Invalid, got {status:?}"
        );
    }

    #[test]
    fn empty_ref_is_invalid() {
        let tmp = env_with_lock();
        let status = classify_pack_ref(tmp.path(), Path::new(""));
        assert!(
            matches!(status, PackRefStatus::Invalid(_)),
            "expected Invalid, got {status:?}"
        );
    }
}
