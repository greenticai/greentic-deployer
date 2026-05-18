//! URI-shaped reference newtypes.
//!
//! - [`SecretRef`] wraps a `secret://<env>/<...>` URI. The runtime resolves the
//!   reference through the env's secrets env-pack; the actual material never
//!   appears in the deployment object model.
//! - [`RuntimeRef`] wraps a `runtime://<env>/discovered/<...>` URI. Values are
//!   resolved through [`EnvironmentRuntime::discovered`](crate::EnvironmentRuntime).

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

const SECRET_SCHEME: &str = "secret://";
const RUNTIME_SCHEME: &str = "runtime://";

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
                Ok(Self(raw))
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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecretRefParseError {
    #[error("secret-ref must start with `secret://`")]
    MissingScheme,
    #[error("secret-ref path is empty")]
    EmptyPath,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RuntimeRefParseError {
    #[error("runtime-ref must start with `runtime://`")]
    MissingScheme,
    #[error("runtime-ref path is empty")]
    EmptyPath,
}
