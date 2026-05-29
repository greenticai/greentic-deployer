//! Identifier newtypes used across the deployment object model.
//!
//! `EnvId` is re-exported from `greentic-types`. `RevisionId` and `DeploymentId`
//! are ULIDs (monotonically sortable, 26-char Crockford base32). `BundleId`,
//! `CustomerId`, `PackId`, and `PartyId` are opaque strings — format and
//! authoritative source live outside this crate.

use serde::{Deserialize, Serialize};
use std::fmt;
use ulid::Ulid;

/// ULID-shaped identifier for a revision (`§5.2`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RevisionId(pub Ulid);

impl RevisionId {
    pub fn new() -> Self {
        Self(Ulid::new())
    }
}

impl Default for RevisionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RevisionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// ULID-shaped identifier for a [`BundleDeployment`](crate::BundleDeployment) (`§5.4`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeploymentId(pub Ulid);

impl DeploymentId {
    pub fn new() -> Self {
        Self(Ulid::new())
    }
}

impl Default for DeploymentId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DeploymentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// ULID-shaped identifier for a
/// [`MessagingEndpoint`](crate::MessagingEndpoint) (`Phase M`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MessagingEndpointId(pub Ulid);

impl MessagingEndpointId {
    pub fn new() -> Self {
        Self(Ulid::new())
    }
}

impl Default for MessagingEndpointId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for MessagingEndpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

macro_rules! string_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn new(s: impl Into<String>) -> Self {
                Self(s.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self(s.to_string())
            }
        }
    };
}

string_id!(
    /// Stable identifier for a bundle (`bundle_id` field across §5.2–5.4).
    BundleId
);

string_id!(
    /// Billing principal identifier (`§5.4`). Defaults to `local-dev` for `local` env.
    CustomerId
);

string_id!(
    /// Pack identifier (`§5.2`). Resolves through the pack store.
    PackId
);

string_id!(
    /// Revenue-share party identifier (`§5.4`).
    PartyId
);
