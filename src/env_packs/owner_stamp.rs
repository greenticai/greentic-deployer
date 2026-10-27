//! The owner stamp a deploy writes on every secret it stages.
//!
//! Shared by the Cloud Run lane (a `greentic-owner` label) and the AWS-ECS lane
//! (a `greentic:owner` tag), so one environment reads as one owner on both and
//! the conflict check means the same thing everywhere. Ungated: neither cloud
//! feature owns it.

/// The value stamped as a staged secret's owner: a GCP-label-safe rendering of
/// `env_id`.
///
/// GCP label values admit only `[a-z0-9_-]{0,63}` while
/// [`EnvId`](greentic_types::EnvId) also admits uppercase and `.`, so the raw id
/// cannot be stamped. **The digest is the identity; the readable prefix is
/// decoration** for the console and the conflict messages. Folding the
/// id into the charset is lossy — `a.b` and `a-b` render identically — so a
/// stamp built from the fold alone would read two environments as one owner and
/// wave through exactly the cross-environment write the check exists to stop.
/// The digest is taken over the ORIGINAL id, which is what keeps them apart.
///
/// 26 bytes of SHA-256 (208 bits, 52 hex chars — the most that fits beside a
/// 10-char prefix inside the 63-char limit). Collision-resistant, not injective:
/// two ids CAN in principle share a stamp, and one that did would be classified
/// the environment's own. At 208 bits that is infeasible to hit by accident
/// or to construct. Do not shorten it — an earlier 32-bit digest here had
/// findable collisions between two valid env ids, which is a full bypass of the
/// ownership boundary.
pub(crate) fn env_owner_stamp(env_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = hex::encode(&Sha256::digest(env_id.as_bytes())[..26]);
    // `EnvId` is ASCII-only, so chars are bytes and 10 + '-' + 52 == 63.
    let readable: String = env_id
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .take(10)
        .collect();
    format!("{readable}-{digest}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_fits_a_gcp_label_and_separates_folded_ids() {
        let a = env_owner_stamp("a.b");
        assert!(a.len() <= 63);
        assert_ne!(a, env_owner_stamp("a-b"));
    }
}
