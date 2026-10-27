//! The ACR credential for the worker's bundle pull (`oci_username` /
//! `oci_password` answers, decision D2).
//!
//! greentic-start reads exactly `OCI_USERNAME` / `OCI_PASSWORD`. The username is
//! plain env (part of the revision intent); the password is an ACA secret
//! referenced by `secretRef`, and only its presence is in the intent.

use std::fmt;

use serde_json::Value;

use super::params::AcaParamsError;

pub(crate) const OCI_USERNAME_ENV: &str = "OCI_USERNAME";
pub(crate) const OCI_PASSWORD_ENV: &str = "OCI_PASSWORD";
pub(crate) const USERNAME_KEY: &str = "oci_username";
pub(crate) const PASSWORD_KEY: &str = "oci_password";

const MAX_USERNAME_LEN: usize = 256;
const MAX_PASSWORD_LEN: usize = 4096;

/// The registry password. Never printed by `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RegistryPassword(String);

impl RegistryPassword {
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RegistryPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RegistryPassword(<redacted>)")
    }
}

/// A complete credential: both halves, or none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegistryCredential {
    username: String,
    password: RegistryPassword,
}

impl RegistryCredential {
    pub(crate) fn username(&self) -> &str {
        &self.username
    }
    pub(crate) fn password(&self) -> &RegistryPassword {
        &self.password
    }
}

fn invalid(key: &str, detail: &str) -> AcaParamsError {
    AcaParamsError::Invalid {
        key: key.to_string(),
        detail: detail.to_string(),
    }
}

fn half<'a>(key: &str, value: Option<&'a Value>) -> Result<Option<&'a str>, AcaParamsError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(AcaParamsError::NotAString(key.to_string())),
    }
}

/// Both set or both blank; a lone half is refused (greentic-start would ignore
/// it). Values are never echoed into an error.
pub(crate) fn parse(
    username: Option<&Value>,
    password: Option<&Value>,
) -> Result<Option<RegistryCredential>, AcaParamsError> {
    let (u, p) = match (half(USERNAME_KEY, username)?, half(PASSWORD_KEY, password)?) {
        (None, None) => return Ok(None),
        (Some(u), Some(p)) => (u, p),
        _ => {
            return Err(invalid(
                USERNAME_KEY,
                "`oci_username` and `oci_password` must both be set, or both left blank",
            ));
        }
    };
    if u.chars().any(char::is_control) {
        return Err(invalid(USERNAME_KEY, "must not contain control characters"));
    }
    if u.len() > MAX_USERNAME_LEN {
        return Err(invalid(USERNAME_KEY, "is too long"));
    }
    if p.chars().any(char::is_control) {
        return Err(invalid(PASSWORD_KEY, "must not contain control characters"));
    }
    if p.len() > MAX_PASSWORD_LEN {
        return Err(invalid(PASSWORD_KEY, "is too long"));
    }
    Ok(Some(RegistryCredential {
        username: u.to_string(),
        password: RegistryPassword(p.to_string()),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn blank_is_none_and_both_set_parses() {
        assert_eq!(parse(None, Some(&json!(" "))).unwrap(), None);
        let c = parse(Some(&json!("tok")), Some(&json!("pw"))).unwrap().unwrap();
        assert_eq!(c.username(), "tok");
        assert_eq!(c.password().expose(), "pw");
    }

    #[test]
    fn a_lone_half_is_refused_without_echo() {
        let e = parse(Some(&json!("tok")), None).unwrap_err().to_string();
        assert!(e.contains("both be set") && !e.contains("tok"), "{e}");
        assert!(parse(Some(&json!("u")), Some(&json!("a\nb"))).is_err());
    }

    #[test]
    fn debug_hides_the_password() {
        let c = parse(Some(&json!("tok")), Some(&json!("hunter2"))).unwrap().unwrap();
        assert!(!format!("{c:?}").contains("hunter2"));
    }
}
