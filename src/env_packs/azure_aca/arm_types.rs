//! Request-side model of one Container App: what the deployer intends to PUT.
//!
//! Secret values live only in [`SecretValue`], whose `Debug` redacts. The only
//! way to put a value into an environment variable is [`EnvEntry::plain`], used
//! for the boot env; seed content and credentials travel as
//! [`EnvEntry::secret_ref`] and so can never appear in a plain `env.value`.

use super::naming::{AppName, RevisionSuffix};

/// A secret value. `Debug` never prints it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SecretValue(String);

impl SecretValue {
    pub(crate) fn new(v: impl Into<String>) -> Self {
        Self(v.into())
    }
    /// For the ONE place that serializes it into an ARM body.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppSecret {
    pub name: String,
    pub value: SecretValue,
}

impl AppSecret {
    pub(crate) fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: SecretValue::new(value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EnvEntry {
    Plain { name: String, value: String },
    SecretRef { name: String, secret: String },
}

impl EnvEntry {
    /// A non-secret value (boot env, a digest).
    pub(crate) fn plain(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self::Plain {
            name: name.into(),
            value: value.into(),
        }
    }
    /// A value sourced from an app secret.
    pub(crate) fn secret_ref(name: impl Into<String>, secret: impl Into<String>) -> Self {
        Self::SecretRef {
            name: name.into(),
            secret: secret.into(),
        }
    }
    pub(crate) fn name(&self) -> &str {
        match self {
            Self::Plain { name, .. } | Self::SecretRef { name, .. } => name,
        }
    }
}

/// One `ingress.traffic[]` entry. Always pins an explicit revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrafficEntry {
    /// Full ACA revision name (`<app>--<suffix>`).
    pub revision_name: String,
    /// Whole percent, 0..=100.
    pub weight: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InitSpec {
    pub image: String,
    pub script: String,
    pub env: Vec<EnvEntry>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RevisionSpec {
    pub suffix: RevisionSuffix,
    pub image: String,
    pub cpu: f64,
    pub memory: String,
    pub env: Vec<EnvEntry>,
    pub init: Option<InitSpec>,
    pub min_replicas: u32,
    pub max_replicas: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AppSpec {
    pub name: AppName,
    pub location: String,
    pub environment_id: String,
    pub tags: Vec<(String, String)>,
    pub target_port: u16,
    pub secrets: Vec<AppSecret>,
    pub traffic: Vec<TrafficEntry>,
    pub revision: RevisionSpec,
}

/// Refusal to change a secret a live revision may reference.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error(
    "secret `{0}` already exists with different content; ACA secrets are content-addressed here and never rewritten"
)]
pub(crate) struct SecretConflict(pub String);
