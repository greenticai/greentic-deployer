//! The fingerprint of what one ACA revision is configured to run.
//!
//! ACA revisions are immutable and carry no labels, so the fingerprint travels as
//! the container env var [`INTENT_ENV`]. A re-warm compares it before changing
//! anything: equal is a no-op, different (or unreadable) is a conflict naming the
//! revision. Same length-prefixed SHA-256, 128-bit hex construction as the AWS and
//! Cloud Run lanes. Secret VALUES are excluded; seed content enters through the
//! content-addressed secret NAMES, which are digests of it.

use greentic_deploy_spec::RevisionId;
use sha2::{Digest, Sha256};

use crate::env_packs::deployer::DeployerError;

/// Container env var the intent is stamped into.
pub(crate) const INTENT_ENV: &str = "GREENTIC_REVISION_INTENT";

#[derive(Debug, Clone, Copy)]
pub(crate) struct IntentInputs<'a> {
    pub image: &'a str,
    pub cpu: &'a str,
    pub memory: &'a str,
    pub min_replicas: u32,
    pub max_replicas: u32,
    /// Content-addressed seed secret names, in emission order.
    pub seed_secrets: &'a [String],
    /// Plain boot env, in emission order (the caller keeps it sorted).
    pub boot_env: &'a [(String, String)],
    /// Names of env vars sourced from secrets (values excluded).
    pub secret_env_names: &'a [&'a str],
    pub seed_init_image: &'a str,
}

pub(crate) fn revision_intent(i: &IntentInputs<'_>) -> String {
    let mut h = Sha256::new();
    let mut tagged = |tag: &[u8], bytes: &[u8]| {
        for part in [tag, bytes] {
            h.update((part.len() as u64).to_le_bytes());
            h.update(part);
        }
    };
    tagged(b"image", i.image.as_bytes());
    tagged(b"cpu", i.cpu.as_bytes());
    tagged(b"memory", i.memory.as_bytes());
    tagged(b"min-replicas", &i.min_replicas.to_le_bytes());
    tagged(b"max-replicas", &i.max_replicas.to_le_bytes());
    for s in i.seed_secrets {
        tagged(b"seed-secret", s.as_bytes());
    }
    for (k, v) in i.boot_env {
        tagged(b"env", k.as_bytes());
        tagged(b"env-value", v.as_bytes());
    }
    for n in i.secret_env_names {
        tagged(b"secret-env", n.as_bytes());
    }
    tagged(b"seed-init-image", i.seed_init_image.as_bytes());
    hex::encode(&h.finalize()[..16])
}

/// What the target saw for a revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LiveIntent {
    Absent,
    Present { intent: Option<String> },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IntentVerdict {
    Create,
    Converge,
    Conflict { live: Option<String> },
}

/// An unstamped revision is a conflict: it cannot be verified.
pub(crate) fn classify(live: LiveIntent, intent: &str) -> IntentVerdict {
    match live {
        LiveIntent::Absent => IntentVerdict::Create,
        LiveIntent::Present { intent: Some(l) } if l == intent => IntentVerdict::Converge,
        LiveIntent::Present { intent: l } => IntentVerdict::Conflict { live: l },
    }
}

pub(crate) fn revision_conflict(
    revision_id: RevisionId,
    intent: &str,
    live: Option<String>,
) -> DeployerError {
    let held = match live {
        Some(l) => format!("holds a different configuration (`{l}`)"),
        None => "carries no configuration stamp, so it cannot be verified".to_string(),
    };
    DeployerError::Provider(format!(
        "Container Apps revision `{revision_id}` already exists and {held}; this warm intends \
         `{intent}`. ACA revisions are immutable, so stage a NEW revision to roll out the \
         changed configuration."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(edit: impl FnOnce(&mut IntentInputs<'_>)) -> String {
        let seeds = vec!["seed-env-aaaaaaaaaaaa".to_string()];
        let env = vec![("A".to_string(), "1".to_string())];
        let mut i = IntentInputs {
            image: "img",
            cpu: "0.5",
            memory: "1Gi",
            min_replicas: 0,
            max_replicas: 1,
            seed_secrets: &seeds,
            boot_env: &env,
            secret_env_names: &[],
            seed_init_image: "busybox",
        };
        edit(&mut i);
        revision_intent(&i)
    }

    #[test]
    fn intent_is_128_bit_hex_and_changes_with_every_input() {
        let b = base(|_| {});
        assert_eq!(b.len(), 32);
        assert_eq!(b, base(|_| {}));
        let changed = [
            base(|i| i.image = "other"),
            base(|i| i.cpu = "1"),
            base(|i| i.memory = "2Gi"),
            base(|i| i.min_replicas = 1),
            base(|i| i.seed_init_image = "x"),
            base(|i| i.secret_env_names = &["OCI_PASSWORD"]),
            base(|i| i.boot_env = &[]),
            base(|i| i.seed_secrets = &[]),
        ];
        for c in changed {
            assert_ne!(c, b);
        }
    }

    #[test]
    fn a_value_cannot_forge_a_field_boundary() {
        let a = base(|i| i.image = "a");
        let b = base(|i| i.image = "ab");
        assert_ne!(a, b);
    }

    #[test]
    fn classify_covers_the_three_cases() {
        assert_eq!(classify(LiveIntent::Absent, "x"), IntentVerdict::Create);
        let same = LiveIntent::Present { intent: Some("x".into()) };
        assert_eq!(classify(same, "x"), IntentVerdict::Converge);
        let diff = LiveIntent::Present { intent: Some("y".into()) };
        assert!(matches!(classify(diff, "x"), IntentVerdict::Conflict { .. }));
        let none = LiveIntent::Present { intent: None };
        assert_eq!(classify(none, "x"), IntentVerdict::Conflict { live: None });
    }
}
