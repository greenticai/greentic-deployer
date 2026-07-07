//! `greentic.pack-list-lock.v1`.
//!
//! Pinned, per-revision list of the `.gtpack` artifacts a revision resolves to.
//! Written under `<env_dir>/<pack_list_lock_ref>` at stage time — the lockfile
//! that [`Revision::pack_list_lock_ref`](crate::Revision) points at — and read
//! by `greentic-start` at boot to build the runner load set.
//!
//! Each [`LockedPack`] carries the env-relative path to an extracted `.gtpack`
//! plus its `sha256:<hex>` content digest, so the boot loader can verify the
//! artifact on disk still matches what was staged before loading it (closing
//! the stage→boot TOCTOU window).

use crate::ids::{PackId, RevisionId};
use crate::version::SchemaVersion;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// One pinned `.gtpack` within a revision's resolved pack list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedPack {
    /// Pack identity, derived from the `.gtpack` file stem at stage time.
    pub pack_id: PackId,
    /// Env-relative path to the extracted `.gtpack` artifact on disk.
    pub path: PathBuf,
    /// Content digest of the artifact at `path`, `sha256:<hex>` (lowercase hex).
    pub digest: String,
}

/// The `pack-list.lock` document for a single revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackListLock {
    pub schema: SchemaVersion,
    /// The revision this lock pins — binds the file to its owner so a misplaced
    /// or cross-revision lock is detectable by the reader.
    pub revision_id: RevisionId,
    pub packs: Vec<LockedPack>,
}

impl PackListLock {
    pub fn schema_str() -> &'static str {
        SchemaVersion::PACK_LIST_LOCK_V1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PackListLock {
        PackListLock {
            schema: SchemaVersion::new(SchemaVersion::PACK_LIST_LOCK_V1),
            revision_id: RevisionId::new(),
            packs: vec![LockedPack {
                pack_id: PackId::new("customer.support"),
                path: PathBuf::from("revisions/01.../customer.support"),
                digest: "sha256:abcdef1234567890".into(),
            }],
        }
    }

    #[test]
    fn schema_str_matches_constant() {
        assert_eq!(PackListLock::schema_str(), SchemaVersion::PACK_LIST_LOCK_V1);
    }

    #[test]
    fn json_round_trip() {
        let original = sample();
        let json = serde_json::to_string(&original).unwrap();
        let back: PackListLock = serde_json::from_str(&json).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn empty_packs_round_trips() {
        let lock = PackListLock {
            schema: SchemaVersion::new(SchemaVersion::PACK_LIST_LOCK_V1),
            revision_id: RevisionId::new(),
            packs: vec![],
        };
        let json = serde_json::to_string(&lock).unwrap();
        let back: PackListLock = serde_json::from_str(&json).unwrap();
        assert!(back.packs.is_empty());
    }
}
