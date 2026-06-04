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
/// Most variants are *core slots*: 1-per-env, bound in
/// [`Environment::packs`](crate::Environment), and demanded by name at compile
/// time via [`Environment::pack_for_slot`](crate::Environment::pack_for_slot).
///
/// `Messaging` and `Extension` are the exceptions — *N-per-env* families whose
/// bindings live in their own collections, never in `packs`:
/// - `Messaging` bindings live in
///   [`Environment::messaging_endpoints`](crate::Environment).
/// - `Extension` bindings live in
///   [`Environment::extensions`](crate::Environment) — an open namespace for
///   config-shaped / N-per-env capabilities resolved by a workload at runtime
///   (`ext://<path>[/<instance>]`), not linked as a typed host interface.
///
/// [`binds_in_packs`](Self::binds_in_packs) is the mechanical test for which
/// group a slot is in. The variants exist so per-slot UI/discovery surfaces can
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
    Extension,
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
        CapabilitySlot::Extension,
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
            CapabilitySlot::Extension => "extension",
        }
    }

    /// Whether bindings for this slot live in
    /// [`Environment::packs`](crate::Environment) under the 1-per-slot rule.
    ///
    /// `true` for the core slots (a workload's platform demands exactly one
    /// binding by name via `pack_for_slot`); `false` for the N-per-env families
    /// (`Messaging`, `Extension`) whose bindings live in their own collections.
    /// This is the single predicate distinguishing the two groups — it gates
    /// `missing_slots` reporting and rejects N-per-env slots from `op env-packs`.
    pub fn binds_in_packs(self) -> bool {
        !matches!(self, CapabilitySlot::Messaging | CapabilitySlot::Extension)
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
            if !descriptor_path_char_ok(ch) {
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

/// Charset permitted in a [`PackDescriptor`] path segment (also the charset an
/// [`ExtensionRef`](crate::ExtensionRef) path must satisfy): ASCII lowercase,
/// digits, `-`, `.`.
pub(crate) fn descriptor_path_char_ok(ch: char) -> bool {
    ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-' || ch == '.'
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

#[cfg(test)]
mod capability_slot_tests {
    use super::*;

    #[test]
    fn as_str_round_trips_for_every_variant() {
        for slot in CapabilitySlot::ALL {
            let s = slot.as_str();
            let back: CapabilitySlot =
                serde_json::from_value(serde_json::Value::String(s.to_string()))
                    .expect("lowercase as_str deserialises back to the variant");
            assert_eq!(back, *slot, "round-trip failed for {s}");
        }
    }

    #[test]
    fn extension_is_an_n_per_env_slot() {
        assert!(!CapabilitySlot::Extension.binds_in_packs());
        assert!(!CapabilitySlot::Messaging.binds_in_packs());
        // Every other slot is a core, 1-per-slot family bound in `packs`.
        for slot in CapabilitySlot::ALL {
            let expect_in_packs =
                !matches!(slot, CapabilitySlot::Messaging | CapabilitySlot::Extension);
            assert_eq!(slot.binds_in_packs(), expect_in_packs, "{slot}");
        }
    }

    #[test]
    fn all_contains_extension_exactly_once() {
        assert_eq!(
            CapabilitySlot::ALL
                .iter()
                .filter(|s| **s == CapabilitySlot::Extension)
                .count(),
            1
        );
    }
}
