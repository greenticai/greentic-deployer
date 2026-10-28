//! The registry credential for the worker's bundle pull (`oci_username` /
//! `oci_password` answers).
//!
//! greentic-start pulls the customer bundle at boot with whatever registry
//! credential it finds in its environment: it reads exactly `OCI_USERNAME` and
//! `OCI_PASSWORD` (`bundle_ref::generic_registry_credentials`, both must be
//! non-empty) and an explicit pair wins over any ambient credential. A private
//! registry therefore needs the pair on the worker container.
//!
//! The username is not secret and rides the plain `environment` (so it is part
//! of the revision intent, exactly like the K8s lane's `OCI_USERNAME` pod
//! variable). The password is secret material: it is staged as the
//! `<secret_prefix>-oci-password` Secrets Manager secret and injected through
//! the task definition's `secrets`, never `environment`. Only its PRESENCE
//! (the env var name) is part of the revision intent.
//!
//! Amazon ECR is deliberately not covered by this pair: ECR has no long-lived
//! password, only 12-hour tokens, so a stored token would crash-loop any task
//! started after it expired (see `docs/aws-ecs-seed-and-bundle-delivery.md`
//! section 4).

use std::fmt;

use serde_json::Value;

use super::deployer::AwsEcsParamsError;

/// Env var greentic-start reads the registry username from.
pub(crate) const OCI_USERNAME_ENV: &str = "OCI_USERNAME";
/// Env var greentic-start reads the registry password from.
pub(crate) const OCI_PASSWORD_ENV: &str = "OCI_PASSWORD";

pub(crate) const USERNAME_KEY: &str = "oci_username";
pub(crate) const PASSWORD_KEY: &str = "oci_password";

const MAX_USERNAME_LEN: usize = 256;
const MAX_PASSWORD_LEN: usize = 4096;

/// The registry password. Never printed by `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RegistryPassword(String);

impl RegistryPassword {
    /// The raw password, for the ONE place that writes it into a secret.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RegistryPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RegistryPassword(<redacted>)")
    }
}

/// A complete registry credential: both halves, or none at all.
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

fn invalid(key: &str, detail: &str) -> AwsEcsParamsError {
    AwsEcsParamsError::Invalid {
        key: key.to_string(),
        detail: detail.to_string(),
    }
}

/// Read one half. A missing, null or blank value is `None`; a non-string is an
/// error. Values are kept verbatim (a password may have meaningful edge
/// spaces) and are never echoed into an error.
fn half<'a>(key: &str, value: Option<&'a Value>) -> Result<Option<&'a str>, AwsEcsParamsError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(AwsEcsParamsError::NotAString(key.to_string())),
    }
}

/// Parse the two answers. Both set or both blank; anything else is refused,
/// because a lone half is almost always an operator mistake and greentic-start
/// would silently ignore it (it needs both).
pub(crate) fn parse(
    username: Option<&Value>,
    password: Option<&Value>,
) -> Result<Option<RegistryCredential>, AwsEcsParamsError> {
    let username = half(USERNAME_KEY, username)?;
    let password = half(PASSWORD_KEY, password)?;
    let (username, password) = match (username, password) {
        (None, None) => return Ok(None),
        (Some(u), Some(p)) => (u, p),
        _ => {
            return Err(invalid(
                USERNAME_KEY,
                "`oci_username` and `oci_password` must both be set, or both left blank",
            ));
        }
    };
    if username.chars().any(char::is_control) {
        return Err(invalid(USERNAME_KEY, "must not contain control characters"));
    }
    if username.len() > MAX_USERNAME_LEN {
        return Err(invalid(
            USERNAME_KEY,
            &format!("is longer than {MAX_USERNAME_LEN} bytes"),
        ));
    }
    if password.chars().any(char::is_control) {
        return Err(invalid(PASSWORD_KEY, "must not contain control characters"));
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(invalid(
            PASSWORD_KEY,
            &format!("is longer than {MAX_PASSWORD_LEN} bytes"),
        ));
    }
    Ok(Some(RegistryCredential {
        username: username.to_string(),
        password: RegistryPassword(password.to_string()),
    }))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn p(
        u: Option<Value>,
        pw: Option<Value>,
    ) -> Result<Option<RegistryCredential>, AwsEcsParamsError> {
        parse(u.as_ref(), pw.as_ref())
    }

    #[test]
    fn both_blank_or_absent_is_no_credential() {
        assert_eq!(p(None, None).unwrap(), None);
        assert_eq!(p(Some(json!(" ")), Some(json!(""))).unwrap(), None);
        assert_eq!(p(Some(Value::Null), None).unwrap(), None);
    }

    #[test]
    fn both_set_parses_verbatim() {
        let c = p(Some(json!("robot")), Some(json!(" pw ")))
            .unwrap()
            .unwrap();
        assert_eq!(c.username(), "robot");
        assert_eq!(c.password().expose(), " pw ");
    }

    #[test]
    fn a_lone_half_is_refused_without_echoing_the_value() {
        for (u, pw) in [
            (Some(json!("robot")), None),
            (None, Some(json!("hunter2-secret"))),
        ] {
            let err = p(u, pw).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("both be set"), "{msg}");
            assert!(
                !msg.contains("hunter2-secret") && !msg.contains("robot"),
                "{msg}"
            );
        }
    }

    #[test]
    fn non_strings_and_control_characters_are_refused() {
        assert!(matches!(
            p(Some(json!(1)), Some(json!("x"))).unwrap_err(),
            AwsEcsParamsError::NotAString(k) if k == "oci_username"
        ));
        assert!(matches!(
            p(Some(json!("u")), Some(json!(true))).unwrap_err(),
            AwsEcsParamsError::NotAString(k) if k == "oci_password"
        ));
        for (u, pw, key) in [
            ("u\n", "x", "oci_username"),
            ("u", "x\0y", "oci_password"),
            ("u", "x\ny", "oci_password"),
        ] {
            let err = p(Some(json!(u)), Some(json!(pw))).unwrap_err();
            assert!(
                matches!(&err, AwsEcsParamsError::Invalid { key: k, .. } if k == key),
                "{err}"
            );
        }
    }

    #[test]
    fn length_caps_apply() {
        let long = "a".repeat(MAX_PASSWORD_LEN + 1);
        assert!(p(Some(json!("u")), Some(json!(long))).is_err());
        let long_user = "a".repeat(MAX_USERNAME_LEN + 1);
        assert!(p(Some(json!(long_user)), Some(json!("x"))).is_err());
    }

    #[test]
    fn debug_never_shows_the_password() {
        let c = p(Some(json!("robot")), Some(json!("hunter2-secret")))
            .unwrap()
            .unwrap();
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("hunter2-secret"), "{dbg}");
        assert!(dbg.contains("robot") && dbg.contains("<redacted>"), "{dbg}");
    }
}
