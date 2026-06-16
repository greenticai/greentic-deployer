//! The write side of the "move secrets into the deployment target" seam.
//!
//! `gtc start` resolves runtime secrets from the local secrets manager and then
//! *moves* them into the deployment target's secrets manager. That second step
//! talks to a live provider (today AWS Secrets Manager via the `aws` CLI), which
//! makes the promotion behaviour awkward to test.
//!
//! [`RuntimeSecretSink`] abstracts the per-secret write so the orchestration in
//! [`promote_runtime_secrets`] — naming, tagging, idempotency, and the promotion
//! report — is exercised against an in-memory mock instead of a real provider.

use crate::error::Result;
use crate::runtime_secrets::{
    PromoteRuntimeSecretsReport, PromotedRuntimeSecret, ResolvedRuntimeSecret, cloud_secret_name,
};

/// Outcome of writing a single secret to the target secrets manager.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpsertOutcome {
    /// The secret did not exist and was created.
    Created,
    /// The secret already existed and its value was overwritten.
    Updated,
}

/// Write side of a cloud secrets manager.
///
/// Implementations must be idempotent: writing the same name twice overwrites
/// the value (returning [`UpsertOutcome::Updated`] the second time).
pub trait RuntimeSecretSink {
    /// Create `name` with `value`, or overwrite the value if it already exists.
    fn upsert(&self, name: &str, value: &str, tags: &[(String, String)]) -> Result<UpsertOutcome>;
}

/// Build the canonical tag set applied to a promoted secret.
pub fn runtime_secret_tags(
    secret_uri: &str,
    bundle_digest: Option<&str>,
    environment: &str,
    tenant: &str,
    team: &str,
    provider: &str,
    secret_manager: &str,
) -> Vec<(String, String)> {
    let mut tags = vec![
        (
            "greentic:managed-by".to_string(),
            "greentic-deployer".to_string(),
        ),
        ("greentic:provider".to_string(), provider.to_string()),
        (
            "greentic:secret-manager".to_string(),
            secret_manager.to_string(),
        ),
        ("greentic:environment".to_string(), environment.to_string()),
        ("greentic:tenant".to_string(), tenant.to_string()),
        ("greentic:team".to_string(), team.to_string()),
        ("greentic:secret-uri".to_string(), secret_uri.to_string()),
    ];
    if let Some(digest) = bundle_digest {
        tags.push(("greentic:bundle-digest".to_string(), digest.to_string()));
    }
    tags
}

/// Move resolved runtime secrets into the target secrets manager through `sink`.
///
/// Each secret is written under its canonical cloud name (`cloud_secret_name`)
/// with the standard tag set; the returned report lists what was promoted.
pub fn promote_runtime_secrets(
    sink: &dyn RuntimeSecretSink,
    resolved: &[ResolvedRuntimeSecret],
    prefix: &str,
    bundle_digest: Option<&str>,
    environment: &str,
    tenant: &str,
    team: &str,
    provider: &str,
    secret_manager: &str,
) -> Result<PromoteRuntimeSecretsReport> {
    let mut report = PromoteRuntimeSecretsReport::default();
    for secret in resolved {
        let remote_name = cloud_secret_name(
            prefix,
            &secret.requirement.provider_id,
            &secret.requirement.key,
        );
        let tags = runtime_secret_tags(
            &secret.requirement.uri,
            bundle_digest,
            environment,
            tenant,
            team,
            provider,
            secret_manager,
        );
        sink.upsert(&remote_name, secret.value.expose(), &tags)?;
        report.promoted.push(PromotedRuntimeSecret {
            uri: secret.requirement.uri.clone(),
            remote_name,
        });
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DeployerError;
    use crate::runtime_secrets::{RuntimeSecretRequirement, SecretValue};
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RecordedPut {
        name: String,
        value: String,
        tags: Vec<(String, String)>,
        outcome: UpsertOutcome,
    }

    /// In-memory sink that records every write and mimics create-or-update.
    #[derive(Default)]
    struct RecordingSink {
        puts: RefCell<Vec<RecordedPut>>,
        store: RefCell<BTreeMap<String, String>>,
        fail_on: Option<String>,
    }

    impl RuntimeSecretSink for RecordingSink {
        fn upsert(
            &self,
            name: &str,
            value: &str,
            tags: &[(String, String)],
        ) -> Result<UpsertOutcome> {
            if self.fail_on.as_deref() == Some(name) {
                return Err(DeployerError::Other(format!("sink rejected {name}")));
            }
            let existed = self
                .store
                .borrow_mut()
                .insert(name.to_string(), value.to_string())
                .is_some();
            let outcome = if existed {
                UpsertOutcome::Updated
            } else {
                UpsertOutcome::Created
            };
            self.puts.borrow_mut().push(RecordedPut {
                name: name.to_string(),
                value: value.to_string(),
                tags: tags.to_vec(),
                outcome,
            });
            Ok(outcome)
        }
    }

    fn make_resolved(provider_id: &str, key: &str, value: &str) -> ResolvedRuntimeSecret {
        ResolvedRuntimeSecret {
            requirement: RuntimeSecretRequirement {
                uri: format!("secrets://dev/demo/_/{provider_id}/{key}"),
                provider_id: provider_id.to_string(),
                key: key.to_string(),
                required: true,
                default_value: None,
                generated: None,
                source: PathBuf::from("packs/demo"),
            },
            value: SecretValue::new(value.to_string()),
            source: crate::runtime_secrets::SecretValueSource::DevStore {
                path: PathBuf::from(".greentic/dev/.dev.secrets.env"),
            },
        }
    }

    #[test]
    fn promotes_each_secret_with_canonical_name_value_and_tags() {
        let sink = RecordingSink::default();
        let resolved = vec![
            make_resolved("messaging-webchat-gui", "jwt_signing_key", "generated-key"),
            make_resolved("deep-research-demo", "api_key_secret", "sk-real"),
        ];

        let report = promote_runtime_secrets(
            &sink,
            &resolved,
            "greentic/dev/demo/_",
            Some("sha256:abc"),
            "dev",
            "demo",
            "_",
            "aws",
            "aws-secrets-manager",
        )
        .expect("promote");

        assert_eq!(report.promoted.len(), 2);
        let puts = sink.puts.borrow();
        assert_eq!(puts.len(), 2);
        assert_eq!(
            puts[0].name,
            "greentic/dev/demo/_/messaging_webchat_gui/jwt_signing_key"
        );
        assert_eq!(puts[0].value, "generated-key");
        assert_eq!(puts[0].outcome, UpsertOutcome::Created);
        assert!(
            puts[0]
                .tags
                .iter()
                .any(|(k, v)| k == "greentic:secret-uri"
                    && v == "secrets://dev/demo/_/messaging-webchat-gui/jwt_signing_key")
        );
        assert!(
            puts[0]
                .tags
                .iter()
                .any(|(k, v)| k == "greentic:bundle-digest" && v == "sha256:abc")
        );
        assert_eq!(puts[1].value, "sk-real");
    }

    #[test]
    fn re_promoting_same_secret_overwrites_idempotently() {
        let sink = RecordingSink::default();
        let resolved = vec![make_resolved("p", "k", "v1")];
        promote_runtime_secrets(
            &sink, &resolved, "greentic/dev/demo/_", None, "dev", "demo", "_", "aws", "sm",
        )
        .expect("first");

        let resolved = vec![make_resolved("p", "k", "v2")];
        promote_runtime_secrets(
            &sink, &resolved, "greentic/dev/demo/_", None, "dev", "demo", "_", "aws", "sm",
        )
        .expect("second");

        let puts = sink.puts.borrow();
        assert_eq!(puts.len(), 2);
        assert_eq!(puts[0].outcome, UpsertOutcome::Created);
        assert_eq!(puts[1].outcome, UpsertOutcome::Updated);
        assert_eq!(sink.store.borrow().get("greentic/dev/demo/_/p/k").unwrap(), "v2");
    }

    #[test]
    fn promotion_propagates_sink_failure() {
        let sink = RecordingSink {
            fail_on: Some("greentic/dev/demo/_/p/k".to_string()),
            ..Default::default()
        };
        let resolved = vec![make_resolved("p", "k", "v")];
        let err = promote_runtime_secrets(
            &sink, &resolved, "greentic/dev/demo/_", None, "dev", "demo", "_", "aws", "sm",
        )
        .unwrap_err();
        assert!(err.to_string().contains("sink rejected"));
    }

    #[test]
    fn empty_resolved_set_promotes_nothing() {
        let sink = RecordingSink::default();
        let report = promote_runtime_secrets(
            &sink, &[], "greentic/dev/demo/_", None, "dev", "demo", "_", "aws", "sm",
        )
        .expect("promote");
        assert!(report.promoted.is_empty());
        assert!(sink.puts.borrow().is_empty());
    }

    #[test]
    fn tags_include_management_scope_and_bundle_digest() {
        let tags = runtime_secret_tags(
            "secrets://dev/demo/_/messaging-webchat-gui/jwt_signing_key",
            Some("sha256:bundle"),
            "dev",
            "demo",
            "_",
            "aws",
            "aws-secrets-manager",
        );
        assert!(tags.contains(&("greentic:managed-by".into(), "greentic-deployer".into())));
        assert!(tags.contains(&(
            "greentic:secret-manager".into(),
            "aws-secrets-manager".into()
        )));
        assert!(tags.contains(&("greentic:environment".into(), "dev".into())));
        assert!(tags.contains(&("greentic:tenant".into(), "demo".into())));
        assert!(tags.contains(&("greentic:team".into(), "_".into())));
        assert!(tags.contains(&("greentic:bundle-digest".into(), "sha256:bundle".into())));
        assert!(tags.iter().any(|(key, value)| {
            key == "greentic:secret-uri" && value.contains("messaging-webchat-gui")
        }));
    }

    #[test]
    fn tags_omit_bundle_digest_when_absent() {
        let tags = runtime_secret_tags(
            "secrets://dev/demo/_/deep-research-demo/api_key_secret",
            None,
            "dev",
            "demo",
            "_",
            "aws",
            "aws-secrets-manager",
        );
        assert!(tags.contains(&("greentic:provider".into(), "aws".into())));
        assert!(
            !tags
                .iter()
                .any(|(key, _value)| key == "greentic:bundle-digest")
        );
    }
}
