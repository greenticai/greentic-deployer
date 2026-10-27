//! The fingerprint of what one ECS revision is configured to run.
//!
//! The AWS twin of Cloud Run's `revision_intent`: the revision's task
//! definition is stamped with it (tag [`REVISION_INTENT_TAG_KEY`]) and a re-warm
//! compares it before staging anything. A task set's name is a pure function
//! of `(deployment, revision)` while its image, size, count and boot env come
//! from the binding's answers, which the operator can edit between warms; so a
//! live task set is only "the same warm, retried" when its stamp equals what
//! this warm would write. Task definitions are immutable, so a different stamp
//! needs a NEW revision, never an in-place update.
//!
//! Secret VERSIONS and values are excluded for the reason the GCP comment
//! gives: a version is a staging artifact, and the fingerprint must be
//! computable before staging so a retry stages nothing.
//!
//! [`REVISION_INTENT_TAG_KEY`]: super::deploy_target::REVISION_INTENT_TAG_KEY

use greentic_deploy_spec::RevisionId;

use super::deploy_target::LiveTaskSet;
use crate::env_packs::deployer::DeployerError;

/// SHA-256 over length-prefixed fields, truncated to 128 bits of lowercase hex
/// (32 chars, well inside an ECS tag value's 256-char limit). Length prefixes
/// keep a value from forging a field boundary. `cpu` / `memory` are hashed
/// only when set (a binding with no launch config has none), and each secret
/// env NAME is hashed only when present, so an environment with no telemetry
/// header keeps its fingerprint.
pub(crate) fn revision_intent(
    image: &str,
    cpu: &str,
    memory: &str,
    desired_count: u32,
    secret_name: &str,
    boot_env: &[(String, String)],
    secret_env_names: &[&str],
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut field = |bytes: &[u8]| {
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    };
    field(image.as_bytes());
    if !cpu.is_empty() {
        field(b"cpu");
        field(cpu.as_bytes());
    }
    if !memory.is_empty() {
        field(b"memory");
        field(memory.as_bytes());
    }
    field(&desired_count.to_le_bytes());
    field(secret_name.as_bytes());
    for (key, value) in boot_env {
        field(key.as_bytes());
        field(value.as_bytes());
    }
    for name in secret_env_names {
        field(b"secret-env");
        field(name.as_bytes());
    }
    hex::encode(&hasher.finalize()[..16])
}

/// What a re-warm should do with the revision's live task set.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IntentVerdict {
    /// Nothing there: stage the seed and create the task set.
    Create,
    /// The same configuration is already live: converge, stage nothing.
    Converge,
    /// The revision holds another configuration, or none that can be checked.
    Conflict { live: Option<String> },
}

/// Classify the live task set against this warm's `intent`. An unstamped task
/// set is a conflict: it cannot be verified, and adopting it could report a
/// changed configuration as live while the old one serves.
pub(crate) fn classify(live: LiveTaskSet, intent: &str) -> IntentVerdict {
    match live {
        LiveTaskSet::Absent => IntentVerdict::Create,
        LiveTaskSet::Present { intent: Some(live) } if live == intent => IntentVerdict::Converge,
        LiveTaskSet::Present { intent: live } => IntentVerdict::Conflict { live },
    }
}

/// The refusal for a revision whose task set holds another configuration.
pub(crate) fn revision_conflict(
    revision_id: RevisionId,
    intent: &str,
    live: Option<String>,
) -> DeployerError {
    let held = match live {
        Some(live) => format!("holds a different configuration (`{live}`)"),
        None => "carries no configuration stamp, so it cannot be verified".to_string(),
    };
    DeployerError::Provider(format!(
        "ECS revision `{revision_id}` already exists and {held}; this warm intends `{intent}`. \
         ECS task definitions are immutable, so the live one cannot be updated in place — stage \
         a NEW revision to roll out the changed configuration."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> String {
        revision_intent(
            "img",
            "256",
            "512",
            1,
            "gtc-e-environment",
            &[("A".into(), "1".into())],
            &[],
        )
    }

    #[test]
    fn intent_is_32_hex_and_deterministic() {
        let a = base();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(a, base());
    }

    #[test]
    fn every_field_moves_the_intent() {
        let a = base();
        let env = [("A".to_string(), "1".to_string())];
        assert_ne!(
            a,
            revision_intent("img2", "256", "512", 1, "gtc-e-environment", &env, &[])
        );
        assert_ne!(
            a,
            revision_intent("img", "512", "512", 1, "gtc-e-environment", &env, &[])
        );
        assert_ne!(
            a,
            revision_intent("img", "256", "1024", 1, "gtc-e-environment", &env, &[])
        );
        assert_ne!(
            a,
            revision_intent("img", "256", "512", 2, "gtc-e-environment", &env, &[])
        );
        assert_ne!(
            a,
            revision_intent("img", "256", "512", 1, "other", &env, &[])
        );
        assert_ne!(
            a,
            revision_intent("img", "256", "512", 1, "gtc-e-environment", &[], &[])
        );
        assert_ne!(
            a,
            revision_intent("img", "256", "512", 1, "gtc-e-environment", &env, &["H"])
        );
    }

    #[test]
    fn length_prefixes_stop_boundary_forgery() {
        let one = [("AB".to_string(), "C".to_string())];
        let two = [("A".to_string(), "BC".to_string())];
        assert_ne!(
            revision_intent("i", "", "", 1, "s", &one, &[]),
            revision_intent("i", "", "", 1, "s", &two, &[])
        );
    }

    #[test]
    fn unset_cpu_and_memory_are_not_hashed() {
        assert_ne!(
            revision_intent("i", "", "", 1, "s", &[], &[]),
            revision_intent("i", "256", "", 1, "s", &[], &[])
        );
    }

    #[test]
    fn classify_covers_the_three_states() {
        assert_eq!(classify(LiveTaskSet::Absent, "x"), IntentVerdict::Create);
        assert_eq!(
            classify(
                LiveTaskSet::Present {
                    intent: Some("x".into())
                },
                "x"
            ),
            IntentVerdict::Converge
        );
        assert_eq!(
            classify(
                LiveTaskSet::Present {
                    intent: Some("y".into())
                },
                "x"
            ),
            IntentVerdict::Conflict {
                live: Some("y".into())
            }
        );
        assert_eq!(
            classify(LiveTaskSet::Present { intent: None }, "x"),
            IntentVerdict::Conflict { live: None }
        );
    }
}
