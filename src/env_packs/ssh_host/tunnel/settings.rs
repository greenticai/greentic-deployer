//! Declarative, strict validation of a tunnel's `settings` map.
//!
//! Every value is checked against an ALLOW-list for its [`ValueKind`], so
//! nothing a shell or an option parser would interpret (whitespace, `;`, `$(`,
//! backticks, quotes, `..`, a newline, a leading `-`) can get through. Errors
//! name the key and the rule, never the value.

use std::collections::BTreeMap;

use super::TunnelError;

/// What a setting's value is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    /// Hostname or IPv4 address.
    Host,
    /// Account name.
    Account,
    /// TCP port, 1..=65535.
    Port,
    /// Absolute local path, `[A-Za-z0-9._/-]`, no `..`.
    Path,
    /// A short token: letters, digits, `.`, `_`, `-`.
    Word,
    /// `true` or `false`.
    Bool,
    /// One of a fixed list.
    Choice(&'static [&'static str]),
    /// `pin-sha256:` followed by a base64 (43-44 chars) or hex (64 chars) digest.
    PinSha256,
}

/// One accepted setting.
#[derive(Debug, Clone, Copy)]
pub struct SettingSpec {
    pub key: &'static str,
    pub required: bool,
    pub kind: ValueKind,
}

impl SettingSpec {
    pub const fn required(key: &'static str, kind: ValueKind) -> Self {
        Self {
            key,
            required: true,
            kind,
        }
    }

    pub const fn optional(key: &'static str, kind: ValueKind) -> Self {
        Self {
            key,
            required: false,
            kind,
        }
    }
}

/// Check `settings` against `specs` for provider `kind`: no unknown key, every
/// required key present, every value well formed.
pub fn validate_settings(
    kind: &str,
    specs: &[SettingSpec],
    settings: &BTreeMap<String, String>,
) -> Result<(), TunnelError> {
    for key in settings.keys() {
        if !specs.iter().any(|s| s.key == key) {
            return Err(TunnelError::invalid(
                kind,
                &safe_key(key),
                "unknown setting",
            ));
        }
    }
    for spec in specs {
        match settings.get(spec.key) {
            None if spec.required => {
                return Err(TunnelError::invalid(kind, spec.key, "is required"));
            }
            None => {}
            Some(value) => check_value(spec.kind, value)
                .map_err(|detail| TunnelError::invalid(kind, spec.key, detail))?,
        }
    }
    Ok(())
}

/// For kinds this build recognises but cannot bring up: keys are short
/// lowercase names and values are safe text, nothing else is promised.
pub fn validate_unspecified(
    kind: &str,
    settings: &BTreeMap<String, String>,
) -> Result<(), TunnelError> {
    for (key, value) in settings {
        let key_ok = !key.is_empty()
            && key.len() <= 40
            && key
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if !key_ok {
            return Err(TunnelError::invalid(
                kind,
                &safe_key(key),
                "setting names are lowercase letters, digits and `_`",
            ));
        }
        let value_ok = !value.is_empty()
            && value.len() <= 253
            && !value.contains("..")
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-' | ':'));
        if !value_ok {
            return Err(TunnelError::invalid(
                kind,
                key,
                "must be letters, digits, `.`, `_`, `/`, `-`, `:` (no `..`)",
            ));
        }
    }
    Ok(())
}

/// A setting NAME is attacker text too; show it escaped and bounded.
fn safe_key(key: &str) -> String {
    key.chars().take(40).flat_map(char::escape_debug).collect()
}

fn check_value(kind: ValueKind, value: &str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err("must not be empty");
    }
    if value.contains("..") {
        return Err("must not contain `..`");
    }
    match kind {
        ValueKind::Host => host(value),
        ValueKind::Account => account(value),
        ValueKind::Port => port(value),
        ValueKind::Path => path(value),
        ValueKind::Word => word(value),
        ValueKind::Bool => match value {
            "true" | "false" => Ok(()),
            _ => Err("must be `true` or `false`"),
        },
        ValueKind::Choice(options) => {
            if options.contains(&value) {
                Ok(())
            } else {
                Err("is not one of the accepted values")
            }
        }
        ValueKind::PinSha256 => pin(value),
    }
}

fn host(v: &str) -> Result<(), &'static str> {
    if v.len() <= 253
        && !v.starts_with('-')
        && !v.starts_with('.')
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
    {
        Ok(())
    } else {
        Err("must be a hostname or IPv4 address (letters, digits, `.`, `-`; no leading `-`)")
    }
}

fn account(v: &str) -> Result<(), &'static str> {
    if v.len() <= 64
        && !v.starts_with('-')
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
    {
        Ok(())
    } else {
        Err("must be an account name (letters, digits, `.`, `_`, `-`, `@`; no leading `-`)")
    }
}

fn port(v: &str) -> Result<(), &'static str> {
    match v.parse::<u32>() {
        Ok(p) if (1..=65535).contains(&p) && v.chars().all(|c| c.is_ascii_digit()) => Ok(()),
        _ => Err("must be a port number between 1 and 65535"),
    }
}

fn path(v: &str) -> Result<(), &'static str> {
    let ok_chars = v
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'));
    if !v.starts_with('/') || !ok_chars {
        return Err("must be an absolute path of letters, digits, `.`, `_`, `/`, `-`");
    }
    if v == "/" || v[1..].split('/').any(|s| s.is_empty() || s == ".") {
        return Err("must not be `/` or contain an empty or `.` segment");
    }
    Ok(())
}

fn word(v: &str) -> Result<(), &'static str> {
    if v.len() <= 64
        && !v.starts_with('-')
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        Ok(())
    } else {
        Err("must be letters, digits, `.`, `_`, `-` (max 64, no leading `-`)")
    }
}

fn pin(v: &str) -> Result<(), &'static str> {
    let Some(digest) = v.strip_prefix("pin-sha256:") else {
        return Err("must start with `pin-sha256:`");
    };
    let hex = digest.len() == 64 && digest.chars().all(|c| c.is_ascii_hexdigit());
    let b64 = (43..=44).contains(&digest.len())
        && digest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='));
    if hex || b64 {
        Ok(())
    } else {
        Err("must be pin-sha256:<base64 or hex SHA-256 of the gateway's public key>")
    }
}
