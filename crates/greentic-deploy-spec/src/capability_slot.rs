//! Capability slot enumeration and pack descriptors (`§5.1`).
//!
//! [`CapabilitySlot`] is the *closed* enum of capability families an Environment
//! can bind. Adding a new family is a deploy-spec schema bump.
//!
//! [`PackDescriptor`] is the *open* string identifying a specific implementation
//! pack within a slot (e.g. `greentic.deployer.k8s@1.0.0`). Adding a new K8s
//! deployer is a new descriptor value, not a new enum variant.

use crate::version::SemVer;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// Closed enumeration of capability slots an Environment can bind (`§5.1`).
///
/// `Messaging` is reserved for Phase M endpoints but bindings live in
/// [`Environment::messaging_endpoints`](crate::Environment), not in
/// [`Environment::packs`](crate::Environment) — messaging endpoints are
/// N-per-env, so the 1-per-slot constraint enforced on `packs` does not
/// apply. The variant exists so future per-slot UI/discovery surfaces can
/// enumerate every capability family from one source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapabilitySlot {
    Deployer,
    Secrets,
    Telemetry,
    Sessions,
    State,
    Revocation,
    Messaging,
}

impl CapabilitySlot {
    pub const ALL: &'static [CapabilitySlot] = &[
        CapabilitySlot::Deployer,
        CapabilitySlot::Secrets,
        CapabilitySlot::Telemetry,
        CapabilitySlot::Sessions,
        CapabilitySlot::State,
        CapabilitySlot::Revocation,
        CapabilitySlot::Messaging,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            CapabilitySlot::Deployer => "deployer",
            CapabilitySlot::Secrets => "secrets",
            CapabilitySlot::Telemetry => "telemetry",
            CapabilitySlot::Sessions => "sessions",
            CapabilitySlot::State => "state",
            CapabilitySlot::Revocation => "revocation",
            CapabilitySlot::Messaging => "messaging",
        }
    }
}

impl fmt::Display for CapabilitySlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Open-form pack descriptor: `<namespace>.<id>@<semver>` (`§5.1`).
///
/// The descriptor must contain at least one `.` in the path segment and a valid
/// SemVer after the `@`. The crate intentionally does NOT enumerate known
/// descriptor strings — adding a new pack is a value, not a schema change.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PackDescriptor {
    raw: String,
    path: String,
    version: SemVer,
}

impl PackDescriptor {
    pub fn try_new(raw: impl Into<String>) -> Result<Self, PackDescriptorParseError> {
        let raw = raw.into();
        Self::parse(&raw).map(|(path, version)| Self { raw, path, version })
    }

    fn parse(s: &str) -> Result<(String, SemVer), PackDescriptorParseError> {
        let mut parts = s.splitn(2, '@');
        let path = parts.next().unwrap_or("");
        let version = parts
            .next()
            .ok_or(PackDescriptorParseError::MissingVersion)?;
        if parts.next().is_some() {
            return Err(PackDescriptorParseError::MultipleAt);
        }
        if path.is_empty() {
            return Err(PackDescriptorParseError::EmptyPath);
        }
        if !path.contains('.') {
            return Err(PackDescriptorParseError::PathMissingDot);
        }
        for ch in path.chars() {
            if !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-' || ch == '.') {
                return Err(PackDescriptorParseError::InvalidPathChar(ch));
            }
        }
        let version = version
            .parse::<SemVer>()
            .map_err(|err| PackDescriptorParseError::InvalidSemver(err.to_string()))?;
        Ok((path.to_string(), version))
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn version(&self) -> &SemVer {
        &self.version
    }
}

impl fmt::Display for PackDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl FromStr for PackDescriptor {
    type Err = PackDescriptorParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s)
    }
}

impl TryFrom<String> for PackDescriptor {
    type Error = PackDescriptorParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl From<PackDescriptor> for String {
    fn from(value: PackDescriptor) -> Self {
        value.raw
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PackDescriptorParseError {
    #[error("pack descriptor missing `@<semver>` suffix")]
    MissingVersion,
    #[error("pack descriptor contains more than one `@` separator")]
    MultipleAt,
    #[error("pack descriptor path is empty")]
    EmptyPath,
    #[error("pack descriptor path must contain at least one `.`")]
    PathMissingDot,
    #[error("pack descriptor path contains invalid character `{0}`")]
    InvalidPathChar(char),
    #[error("pack descriptor version is not valid SemVer: {0}")]
    InvalidSemver(String),
}
