//! URI-shaped reference newtypes.
//!
//! - [`SecretRef`] wraps a `secret://<env>/<...>` URI. The runtime resolves the
//!   reference through the env's secrets env-pack; the actual material never
//!   appears in the deployment object model.
//! - [`RuntimeRef`] wraps a `runtime://<env>/discovered/<...>` URI. Values are
//!   resolved through [`EnvironmentRuntime::discovered`](crate::EnvironmentRuntime).
//! - [`ExtensionRef`] wraps an `ext://<descriptor-path>[/<instance>]` URI. It
//!   carries **no env segment** (the env is implicit in the resolving
//!   workload's context) and resolves through
//!   [`Environment::extension_for_ref`](crate::Environment::extension_for_ref)
//!   to the bound [`ExtensionBinding`](crate::ExtensionBinding).

use crate::capability_slot::descriptor_path_char_ok;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

const SECRET_SCHEME: &str = "secret://";
const RUNTIME_SCHEME: &str = "runtime://";
const EXTENSION_SCHEME: &str = "ext://";

macro_rules! uri_ref {
    ($(#[$meta:meta])* $name:ident, $err:ident, $scheme:expr) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn try_new(raw: impl Into<String>) -> Result<Self, $err> {
                let raw = raw.into();
                if !raw.starts_with($scheme) {
                    return Err($err::MissingScheme);
                }
                if raw.len() == $scheme.len() {
                    return Err($err::EmptyPath);
                }
                // First segment after the scheme is the env identifier; refs
                // are documented as `<scheme>://<env>/<path...>`. The env
                // segment must be present and non-empty so callers can scope
                // a ref to its owning environment.
                let after_scheme = &raw[$scheme.len()..];
                let env_seg = match after_scheme.find('/') {
                    Some(idx) => &after_scheme[..idx],
                    None => after_scheme,
                };
                if env_seg.is_empty() {
                    return Err($err::EmptyEnvSegment);
                }
                Ok(Self(raw))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// First path segment after the scheme — the env id the ref is
            /// scoped to. Returns `None` if the ref was constructed by a
            /// future version of this crate that bypassed [`Self::try_new`]
            /// (current invariant: `Self::try_new` always populates this).
            pub fn env_segment(&self) -> &str {
                let after_scheme = &self.0[$scheme.len()..];
                match after_scheme.find('/') {
                    Some(idx) => &after_scheme[..idx],
                    None => after_scheme,
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = $err;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::try_new(s)
            }
        }

        impl TryFrom<String> for $name {
            type Error = $err;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::try_new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

uri_ref!(
    /// Reference into the env's secrets env-pack: `secret://<env>/<path>`.
    SecretRef, SecretRefParseError, SECRET_SCHEME
);

uri_ref!(
    /// Reference into [`EnvironmentRuntime::discovered`](crate::EnvironmentRuntime):
    /// `runtime://<env>/discovered/<path>`.
    RuntimeRef, RuntimeRefParseError, RUNTIME_SCHEME
);

/// Charset permitted in an [`ExtensionRef`] / [`ExtensionBinding`](crate::ExtensionBinding)
/// instance id: ASCII lowercase, digits, `-`. Notably excludes `.` and `/` so
/// an instance id can never be confused with a descriptor path segment or
/// inject a second `ext://` path component.
pub(crate) fn instance_id_char_ok(ch: char) -> bool {
    ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-'
}

/// Reference to an env extension binding: `ext://<descriptor-path>[/<instance>]`.
///
/// Unlike [`SecretRef`] / [`RuntimeRef`], an extension ref carries **no env
/// segment** — extensions are resolved within the already-known env context of
/// the workload that names them. `<descriptor-path>` is a
/// [`PackDescriptor`](crate::PackDescriptor) path (version-independent — the
/// binding owns the concrete version); the optional `<instance>` selects one of
/// N instances of the same extension type. Lookup is by `(path, instance_id)`
/// against [`Environment::extensions`](crate::Environment), the same key its
/// uniqueness invariant enforces.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ExtensionRef {
    raw: String,
    path: String,
    instance_id: Option<String>,
}

impl ExtensionRef {
    pub fn try_new(raw: impl Into<String>) -> Result<Self, ExtensionRefParseError> {
        let raw = raw.into();
        let body = raw
            .strip_prefix(EXTENSION_SCHEME)
            .ok_or(ExtensionRefParseError::MissingScheme)?;
        // Split on the FIRST `/` only: everything before is the descriptor
        // path, everything after is the instance id. A second `/` therefore
        // lands inside the instance id and is rejected by its charset, so an
        // extension ref is always exactly two segments.
        let (path, instance) = match body.split_once('/') {
            Some((p, inst)) => (p, Some(inst)),
            None => (body, None),
        };
        if path.is_empty() {
            return Err(ExtensionRefParseError::EmptyPath);
        }
        if !path.contains('.') {
            return Err(ExtensionRefParseError::PathMissingDot);
        }
        if let Some(ch) = path.chars().find(|c| !descriptor_path_char_ok(*c)) {
            return Err(ExtensionRefParseError::InvalidPathChar(ch));
        }
        // Own everything borrowed from `raw` before moving `raw` into `Self`.
        let path = path.to_string();
        let instance_id = instance
            .map(|inst| validate_instance_id(inst).map(str::to_string))
            .transpose()?;
        Ok(Self {
            raw,
            path,
            instance_id,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Version-independent descriptor path the ref selects.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Instance selector, or `None` for the default (unnamed) instance.
    pub fn instance_id(&self) -> Option<&str> {
        self.instance_id.as_deref()
    }
}

/// Validate an extension instance id against [`instance_id_char_ok`], returning
/// it unchanged on success. Shared by [`ExtensionRef`] parsing and
/// [`ExtensionBinding`](crate::ExtensionBinding) validation so a stored binding
/// and a ref that selects it agree on the legal charset.
pub(crate) fn validate_instance_id(inst: &str) -> Result<&str, ExtensionRefParseError> {
    if inst.is_empty() {
        return Err(ExtensionRefParseError::EmptyInstance);
    }
    if let Some(ch) = inst.chars().find(|c| !instance_id_char_ok(*c)) {
        return Err(ExtensionRefParseError::InvalidInstanceChar(ch));
    }
    Ok(inst)
}

impl fmt::Display for ExtensionRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl FromStr for ExtensionRef {
    type Err = ExtensionRefParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s)
    }
}

impl TryFrom<String> for ExtensionRef {
    type Error = ExtensionRefParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl From<ExtensionRef> for String {
    fn from(value: ExtensionRef) -> Self {
        value.raw
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExtensionRefParseError {
    #[error("extension-ref must start with `ext://`")]
    MissingScheme,
    #[error("extension-ref path is empty")]
    EmptyPath,
    #[error("extension-ref path must contain at least one `.`")]
    PathMissingDot,
    #[error("extension-ref path contains invalid character `{0}`")]
    InvalidPathChar(char),
    #[error("extension-ref instance id is empty")]
    EmptyInstance,
    #[error("extension-ref instance id contains invalid character `{0}`")]
    InvalidInstanceChar(char),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecretRefParseError {
    #[error("secret-ref must start with `secret://`")]
    MissingScheme,
    #[error("secret-ref path is empty")]
    EmptyPath,
    #[error("secret-ref must carry an env segment: `secret://<env>/<path>`")]
    EmptyEnvSegment,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RuntimeRefParseError {
    #[error("runtime-ref must start with `runtime://`")]
    MissingScheme,
    #[error("runtime-ref path is empty")]
    EmptyPath,
    #[error("runtime-ref must carry an env segment: `runtime://<env>/<path>`")]
    EmptyEnvSegment,
}

#[cfg(test)]
mod extension_ref_tests {
    use super::*;

    #[test]
    fn parses_path_only() {
        let r = ExtensionRef::try_new("ext://acme.oauth.auth0").unwrap();
        assert_eq!(r.path(), "acme.oauth.auth0");
        assert_eq!(r.instance_id(), None);
        assert_eq!(r.as_str(), "ext://acme.oauth.auth0");
    }

    #[test]
    fn parses_path_with_instance() {
        let r = ExtensionRef::try_new("ext://acme.oauth.auth0/primary").unwrap();
        assert_eq!(r.path(), "acme.oauth.auth0");
        assert_eq!(r.instance_id(), Some("primary"));
    }

    #[test]
    fn rejects_missing_scheme() {
        assert_eq!(
            ExtensionRef::try_new("acme.oauth.auth0").unwrap_err(),
            ExtensionRefParseError::MissingScheme
        );
    }

    #[test]
    fn rejects_empty_path() {
        assert_eq!(
            ExtensionRef::try_new("ext://").unwrap_err(),
            ExtensionRefParseError::EmptyPath
        );
        assert_eq!(
            ExtensionRef::try_new("ext:///primary").unwrap_err(),
            ExtensionRefParseError::EmptyPath
        );
    }

    #[test]
    fn rejects_path_without_dot() {
        assert_eq!(
            ExtensionRef::try_new("ext://oauth").unwrap_err(),
            ExtensionRefParseError::PathMissingDot
        );
    }

    #[test]
    fn rejects_invalid_path_char() {
        assert_eq!(
            ExtensionRef::try_new("ext://Acme.Oauth").unwrap_err(),
            ExtensionRefParseError::InvalidPathChar('A')
        );
    }

    #[test]
    fn rejects_empty_instance() {
        assert_eq!(
            ExtensionRef::try_new("ext://acme.oauth/").unwrap_err(),
            ExtensionRefParseError::EmptyInstance
        );
    }

    #[test]
    fn rejects_second_path_segment_via_instance_charset() {
        // A second `/` lands inside the instance id and is rejected — an
        // extension ref is always exactly two segments.
        assert_eq!(
            ExtensionRef::try_new("ext://acme.oauth/inst/extra").unwrap_err(),
            ExtensionRefParseError::InvalidInstanceChar('/')
        );
    }

    #[test]
    fn rejects_dot_in_instance() {
        assert_eq!(
            ExtensionRef::try_new("ext://acme.oauth/inst.bad").unwrap_err(),
            ExtensionRefParseError::InvalidInstanceChar('.')
        );
    }

    #[test]
    fn serde_round_trips_through_string() {
        let r = ExtensionRef::try_new("ext://acme.oauth.auth0/primary").unwrap();
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, "\"ext://acme.oauth.auth0/primary\"");
        let back: ExtensionRef = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }
}
