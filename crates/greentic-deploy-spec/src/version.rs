//! Schema versioning primitives.
//!
//! Each top-level spec type carries a `schema` field holding a [`SchemaVersion`]
//! discriminator (e.g. `greentic.environment.v1`). The constants below name the
//! canonical schema string for every type in this crate; consumers should match
//! against `SchemaVersion::ENVIRONMENT_V1` rather than the raw string.
//!
//! [`SemVer`] wraps [`semver::Version`] for places where finer-grained version
//! tracking is wanted (revision pack lists, descriptors, etc.).

use serde::{Deserialize, Serialize};
use std::fmt;

/// Top-level schema discriminator string (e.g. `greentic.environment.v1`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SchemaVersion(pub String);

impl SchemaVersion {
    pub const ENVIRONMENT_V1: &'static str = "greentic.environment.v1";
    pub const ENVIRONMENT_RUNTIME_V1: &'static str = "greentic.environment-runtime.v1";
    pub const REVISION_V1: &'static str = "greentic.revision.v1";
    pub const TRAFFIC_SPLIT_V1: &'static str = "greentic.traffic-split.v1";
    pub const BUNDLE_DEPLOYMENT_V1: &'static str = "greentic.bundle-deployment.v1";
    pub const CREDENTIALS_V1: &'static str = "greentic.credentials.v1";
    pub const PACK_CONFIG_V1: &'static str = "greentic.pack-config.v1";
    pub const RUNTIME_CONFIG_V1: &'static str = "greentic.runtime-config.v1";

    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for SchemaVersion {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Semantic version wrapper (re-export with serde glue).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SemVer(pub semver::Version);

impl SemVer {
    pub fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self(semver::Version::new(major, minor, patch))
    }
}

impl fmt::Display for SemVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for SemVer {
    type Err = semver::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}
