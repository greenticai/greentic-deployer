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
use super::deployer::FargateLaunchConfig;
use crate::env_packs::deployer::DeployerError;

/// Everything that is baked into a revision's immutable task definition and
/// task set, and so must be part of its intent.
#[derive(Debug, Clone, Copy)]
pub(crate) struct IntentInputs<'a> {
    /// The worker container's image.
    pub image: &'a str,
    /// The Fargate launch config (roles, network, size, container); `None`
    /// for a binding with no launch answers.
    pub launch: Option<&'a FargateLaunchConfig>,
    /// The service's desired task count.
    pub desired_count: u32,
    /// The environment seed secret the seed-init container reads.
    pub secret_name: &'a str,
    /// The worker's plain boot environment, in emission order.
    pub boot_env: &'a [(String, String)],
    /// Names of the worker's secret env vars (values are excluded).
    pub secret_env_names: &'a [&'a str],
    /// The pinned seed-init (busybox) image.
    pub seed_init_image: &'a str,
    /// The log group retention the warm converges, in days.
    pub log_retention_days: i32,
}

/// SHA-256 over length-prefixed fields, truncated to 128 bits of lowercase hex
/// (32 chars, well inside an ECS tag value's 256-char limit). Length prefixes
/// keep a value from forging a field boundary, and every optional field is
/// preceded by its own tag so two different optional fields cannot collide.
///
/// Fixed field order (changing it changes every intent, which the golden
/// vector test catches): image; then, only when a launch config is set,
/// `execution-role`, `task-role` (only when set), `subnet` per entry and
/// `security-group` per entry (both SORTED, because AWS treats them as sets),
/// `public-ip`, `cpu` and `memory` (each only when non-empty),
/// `container-name`, `container-port`; then the desired count, the seed
/// secret name, the boot env pairs in order, `secret-env` per name (only when
/// present), `seed-init-image` and `log-retention`.
pub(crate) fn revision_intent(inputs: &IntentInputs<'_>) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut tagged = |tag: &[u8], bytes: &[u8]| {
        for part in [tag, bytes] {
            hasher.update((part.len() as u64).to_le_bytes());
            hasher.update(part);
        }
    };
    tagged(b"image", inputs.image.as_bytes());
    if let Some(launch) = inputs.launch {
        tagged(b"execution-role", launch.execution_role_arn.as_bytes());
        if let Some(task_role) = launch.task_role_arn.as_deref() {
            tagged(b"task-role", task_role.as_bytes());
        }
        for subnet in sorted(&launch.subnets) {
            tagged(b"subnet", subnet.as_bytes());
        }
        for group in sorted(&launch.security_groups) {
            tagged(b"security-group", group.as_bytes());
        }
        tagged(b"public-ip", &[u8::from(launch.assign_public_ip)]);
        if !launch.cpu.is_empty() {
            tagged(b"cpu", launch.cpu.as_bytes());
        }
        if !launch.memory.is_empty() {
            tagged(b"memory", launch.memory.as_bytes());
        }
        tagged(b"container-name", launch.container_name.as_bytes());
        tagged(b"container-port", &launch.container_port.to_le_bytes());
    }
    tagged(b"desired-count", &inputs.desired_count.to_le_bytes());
    tagged(b"seed-secret", inputs.secret_name.as_bytes());
    for (key, value) in inputs.boot_env {
        tagged(b"env", key.as_bytes());
        tagged(b"env-value", value.as_bytes());
    }
    for name in inputs.secret_env_names {
        tagged(b"secret-env", name.as_bytes());
    }
    tagged(b"seed-init-image", inputs.seed_init_image.as_bytes());
    tagged(b"log-retention", &inputs.log_retention_days.to_le_bytes());
    hex::encode(&hasher.finalize()[..16])
}

fn sorted(values: &[String]) -> Vec<&str> {
    let mut out: Vec<&str> = values.iter().map(String::as_str).collect();
    out.sort_unstable();
    out
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

    fn launch() -> FargateLaunchConfig {
        FargateLaunchConfig {
            execution_role_arn: "arn:aws:iam::111122223333:role/exec".into(),
            task_role_arn: Some("arn:aws:iam::111122223333:role/task".into()),
            subnets: vec!["subnet-b".into(), "subnet-a".into()],
            security_groups: vec!["sg-2".into(), "sg-1".into()],
            assign_public_ip: false,
            cpu: "256".into(),
            memory: "512".into(),
            container_name: "worker".into(),
            container_port: 8080,
        }
    }

    const ENV: &[(&str, &str)] = &[("A", "1")];

    fn env() -> Vec<(String, String)> {
        ENV.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// The base intent, with `edit` applied to the launch config and the
    /// other inputs.
    fn intent_with(
        edit_launch: impl FnOnce(&mut FargateLaunchConfig),
        edit: impl FnOnce(&mut IntentInputs<'_>),
    ) -> String {
        let mut l = launch();
        edit_launch(&mut l);
        let boot_env = env();
        let mut inputs = IntentInputs {
            image: "img",
            launch: Some(&l),
            desired_count: 1,
            secret_name: "gtc-e-environment",
            boot_env: &boot_env,
            secret_env_names: &[],
            seed_init_image: "busybox@sha256:abc",
            log_retention_days: 30,
        };
        edit(&mut inputs);
        revision_intent(&inputs)
    }

    fn base() -> String {
        intent_with(|_| {}, |_| {})
    }

    #[test]
    fn intent_is_32_hex_and_deterministic() {
        let a = base();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(a, base());
    }

    /// Pins the construction: a change of field order, tag or encoding moves
    /// this value, and every live revision would then read as a conflict.
    #[test]
    fn revision_intent_golden_vector() {
        assert_eq!(base(), "50bb3e07b2714d343a9543a27f70cf47");
    }

    #[test]
    fn image_count_secret_and_env_move_the_intent() {
        let a = base();
        assert_ne!(a, intent_with(|_| {}, |i| i.image = "img2"));
        assert_ne!(a, intent_with(|_| {}, |i| i.desired_count = 2));
        assert_ne!(a, intent_with(|_| {}, |i| i.secret_name = "other"));
        assert_ne!(a, intent_with(|_| {}, |i| i.boot_env = &[]));
        assert_ne!(a, intent_with(|_| {}, |i| i.secret_env_names = &["H"]));
    }

    #[test]
    fn roles_move_the_intent() {
        let a = base();
        assert_ne!(
            a,
            intent_with(
                |l| l.execution_role_arn = "arn:aws:iam::1:role/x".into(),
                |_| {}
            )
        );
        assert_ne!(
            a,
            intent_with(
                |l| l.task_role_arn = Some("arn:aws:iam::1:role/y".into()),
                |_| {}
            )
        );
        assert_ne!(a, intent_with(|l| l.task_role_arn = None, |_| {}));
    }

    #[test]
    fn network_moves_the_intent_but_list_order_does_not() {
        let a = base();
        assert_ne!(
            a,
            intent_with(|l| l.subnets.push("subnet-c".into()), |_| {})
        );
        assert_ne!(
            a,
            intent_with(|l| l.security_groups = vec!["sg-1".into()], |_| {})
        );
        assert_ne!(a, intent_with(|l| l.assign_public_ip = true, |_| {}));
        assert_eq!(
            a,
            intent_with(
                |l| {
                    l.subnets.reverse();
                    l.security_groups.reverse();
                },
                |_| {}
            ),
            "subnets and security groups are sets"
        );
    }

    #[test]
    fn size_and_container_move_the_intent() {
        let a = base();
        assert_ne!(a, intent_with(|l| l.cpu = "512".into(), |_| {}));
        assert_ne!(a, intent_with(|l| l.memory = "1024".into(), |_| {}));
        assert_ne!(a, intent_with(|l| l.container_name = "app".into(), |_| {}));
        assert_ne!(a, intent_with(|l| l.container_port = 9090, |_| {}));
        assert_ne!(a, intent_with(|_| {}, |i| i.launch = None));
    }

    #[test]
    fn seed_init_image_moves_the_intent() {
        assert_ne!(
            base(),
            intent_with(|_| {}, |i| i.seed_init_image = "busybox@sha256:def")
        );
    }

    #[test]
    fn log_retention_moves_the_intent() {
        assert_ne!(base(), intent_with(|_| {}, |i| i.log_retention_days = 14));
    }

    #[test]
    fn length_prefixes_stop_boundary_forgery() {
        let with_env = |boot_env: &[(String, String)]| {
            revision_intent(&IntentInputs {
                image: "i",
                launch: None,
                desired_count: 1,
                secret_name: "s",
                boot_env,
                secret_env_names: &[],
                seed_init_image: "b",
                log_retention_days: 30,
            })
        };
        assert_ne!(
            with_env(&[("AB".to_string(), "C".to_string())]),
            with_env(&[("A".to_string(), "BC".to_string())])
        );
    }

    #[test]
    fn unset_cpu_and_memory_are_not_hashed_as_values() {
        assert_ne!(
            intent_with(|l| l.cpu = String::new(), |_| {}),
            intent_with(|l| l.memory = String::new(), |_| {})
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
