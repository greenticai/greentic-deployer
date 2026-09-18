//! Telemetry answers shared by the K8s and Cloud Run deployer bindings.
//!
//! Two keys, both optional: `telemetry_env` (a map of plain container env
//! vars, exact-name allow-listed) and `telemetry_headers` (the OTLP header
//! credential, carried by each target through its own secret store). The
//! designer composes the profile; the deployer validates and renders it, and
//! contributes exactly one value of its own: `greentic.role` in
//! `OTEL_RESOURCE_ATTRIBUTES`, so a router's records can be told from a
//! worker's. See the greentic-designer spec
//! `2026-09-18-telemetry-delivery-start-and-deployer-design.md` §4.3.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::Value;

pub const TELEMETRY_ENV_KEY: &str = "telemetry_env";
pub const TELEMETRY_HEADERS_KEY: &str = "telemetry_headers";

/// The two names greentic-start and greentic-runner-host read the header
/// string from. Both are rendered from the one secret.
pub const HEADER_ENV_NAMES: [&str; 2] = ["OTEL_EXPORTER_OTLP_HEADERS", "OTLP_HEADERS"];

/// Exact names, never prefixes: `OTEL_` would also admit the header
/// credentials and the certificate/key FILE paths.
const ALLOWED_ENV: &[&str] = &[
    "TELEMETRY_EXPORT",
    "OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_PROTOCOL",
    "OTEL_TRACES_SAMPLER",
    "OTEL_TRACES_SAMPLER_ARG",
    "OTEL_RESOURCE_ATTRIBUTES",
    "OTEL_SERVICE_NAME",
    "GREENTIC_TELEMETRY_ENABLED",
    "GREENTIC_TELEMETRY_EXPORTER",
    "GREENTIC_TELEMETRY_ENDPOINT",
    "GREENTIC_TELEMETRY_SAMPLING",
];

const ENDPOINT_NAMES: &[&str] = &[
    "OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "GREENTIC_TELEMETRY_ENDPOINT",
];
const RESOURCE_ATTRIBUTES: &str = "OTEL_RESOURCE_ATTRIBUTES";
const ROLE_ATTRIBUTE: &str = "greentic.role";
pub(crate) const MAX_ENV_VALUE_LEN: usize = 2048;
pub(crate) const MAX_HEADERS_LEN: usize = 8192;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TelemetryAnswerError {
    #[error("`telemetry_env` must be a JSON object of string values")]
    EnvNotAnObject,
    #[error("`telemetry_env` entry `{0}` must be a string")]
    NotAString(String),
    #[error("`telemetry_env` entry `{0}` is not an allowed telemetry variable")]
    UnknownName(String),
    #[error(
        "`telemetry_env` entry `{0}` carries a credential; put the header string in `telemetry_headers` instead"
    )]
    HeaderInEnv(String),
    #[error("`telemetry_env` entry `{0}` is longer than the allowed length")]
    TooLong(String),
    #[error("`telemetry_env` entry `{0}` must be an absolute http(s) URL with a host")]
    BadEndpoint(String),
    #[error("`telemetry_headers` must be a string")]
    HeadersNotAString,
    #[error("`telemetry_headers` is longer than the allowed length")]
    HeadersTooLong,
}

/// The OTLP header credential. Never printed by `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct TelemetryHeaders(String);

impl TelemetryHeaders {
    /// The raw header string, for the ONE place that writes it into a secret.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for TelemetryHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TelemetryHeaders(<redacted>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TelemetryAnswers {
    env: BTreeMap<String, String>,
    headers: Option<TelemetryHeaders>,
}

impl TelemetryAnswers {
    pub fn is_empty(&self) -> bool {
        self.env.is_empty() && self.headers.is_none()
    }

    pub fn headers(&self) -> Option<&TelemetryHeaders> {
        self.headers.as_ref()
    }

    /// Plain env for one pod role, sorted by name (a stable order keeps an
    /// unchanged answer rendering an unchanged pod spec / revision intent).
    /// Empty when nothing was answered, so an env with no profile renders
    /// exactly what it rendered before these keys existed.
    pub fn env_for_role(&self, role: &str) -> Vec<(String, String)> {
        if self.is_empty() {
            return Vec::new();
        }
        let mut out = self.env.clone();
        let role_attr = format!("{ROLE_ATTRIBUTE}={role}");
        let attrs = match out.remove(RESOURCE_ATTRIBUTES) {
            None => role_attr,
            Some(existing)
                if existing
                    .split(',')
                    .any(|kv| kv.starts_with(&format!("{ROLE_ATTRIBUTE}="))) =>
            {
                existing
            }
            Some(existing) if existing.is_empty() => role_attr,
            Some(existing) => format!("{existing},{role_attr}"),
        };
        out.insert(RESOURCE_ATTRIBUTES.to_string(), attrs);
        out.into_iter().collect()
    }
}

fn is_header_name(name: &str) -> bool {
    name.ends_with("_HEADERS") && (name.starts_with("OTEL_") || name.starts_with("OTLP_"))
}

fn valid_endpoint(raw: &str) -> bool {
    url::Url::parse(raw).ok().is_some_and(|u| {
        matches!(u.scheme(), "http" | "https") && u.host_str().is_some_and(|h| !h.is_empty())
    })
}

/// Parse the two optional answers. `null`, absent, and (for headers) the
/// empty string all mean "not answered".
pub fn parse(
    env: Option<&Value>,
    headers: Option<&Value>,
) -> Result<TelemetryAnswers, TelemetryAnswerError> {
    let mut out = TelemetryAnswers::default();
    match env {
        None | Some(Value::Null) => {}
        Some(Value::Object(map)) => {
            for (name, value) in map {
                if is_header_name(name) {
                    return Err(TelemetryAnswerError::HeaderInEnv(name.clone()));
                }
                if !ALLOWED_ENV.contains(&name.as_str()) {
                    return Err(TelemetryAnswerError::UnknownName(name.clone()));
                }
                let Value::String(value) = value else {
                    return Err(TelemetryAnswerError::NotAString(name.clone()));
                };
                if value.len() > MAX_ENV_VALUE_LEN {
                    return Err(TelemetryAnswerError::TooLong(name.clone()));
                }
                if ENDPOINT_NAMES.contains(&name.as_str()) && !valid_endpoint(value) {
                    return Err(TelemetryAnswerError::BadEndpoint(name.clone()));
                }
                out.env.insert(name.clone(), value.clone());
            }
        }
        Some(_) => return Err(TelemetryAnswerError::EnvNotAnObject),
    }
    match headers {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) if s.trim().is_empty() => {}
        Some(Value::String(s)) if s.len() > MAX_HEADERS_LEN => {
            return Err(TelemetryAnswerError::HeadersTooLong);
        }
        Some(Value::String(s)) => out.headers = Some(TelemetryHeaders(s.clone())),
        Some(_) => return Err(TelemetryAnswerError::HeadersNotAString),
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn env(v: serde_json::Value) -> Result<TelemetryAnswers, TelemetryAnswerError> {
        parse(Some(&v), None)
    }

    #[test]
    fn absent_keys_are_empty() {
        let t = parse(None, None).unwrap();
        assert!(t.is_empty());
        assert!(t.env_for_role("worker").is_empty());
        let t = parse(Some(&serde_json::Value::Null), Some(&json!(""))).unwrap();
        assert!(
            t.is_empty(),
            "null env and blank headers mean 'not answered'"
        );
    }

    #[test]
    fn allowed_names_are_accepted_and_rendered_sorted() {
        let t = env(json!({
            "TELEMETRY_EXPORT": "otlp-grpc",
            "OTLP_ENDPOINT": "http://collector.internal:4317",
            "GREENTIC_TELEMETRY_ENABLED": "1"
        }))
        .unwrap();
        let names: Vec<String> = t
            .env_for_role("worker")
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            names,
            vec![
                "GREENTIC_TELEMETRY_ENABLED",
                "OTEL_RESOURCE_ATTRIBUTES",
                "OTLP_ENDPOINT",
                "TELEMETRY_EXPORT"
            ]
        );
    }

    #[test]
    fn an_unknown_name_is_refused_by_name() {
        let err = env(json!({"FOO": "bar"})).unwrap_err().to_string();
        assert!(err.contains("`FOO`"), "{err}");
    }

    #[test]
    fn a_header_name_inside_telemetry_env_points_at_telemetry_headers() {
        for name in [
            "OTLP_HEADERS",
            "OTEL_EXPORTER_OTLP_HEADERS",
            "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
        ] {
            let err = env(json!({ name: "authorization=Bearer s3cret" }))
                .unwrap_err()
                .to_string();
            assert!(err.contains(TELEMETRY_HEADERS_KEY), "{err}");
            assert!(
                !err.contains("s3cret"),
                "a credential must never reach an error: {err}"
            );
        }
    }

    #[test]
    fn non_string_values_and_non_objects_are_refused() {
        assert!(env(json!({"TELEMETRY_EXPORT": 1})).is_err());
        assert!(env(json!(["TELEMETRY_EXPORT"])).is_err());
        assert!(parse(None, Some(&json!(42))).is_err());
    }

    #[test]
    fn endpoints_must_be_absolute_http_urls_with_any_host() {
        for ok in ["http://collector.internal:4317", "https://otlp.example.com"] {
            assert!(env(json!({"OTLP_ENDPOINT": ok})).is_ok(), "{ok}");
        }
        for bad in ["collector:4317", "ftp://x", "http://", "/relative"] {
            let err = env(json!({"OTEL_EXPORTER_OTLP_ENDPOINT": bad}))
                .unwrap_err()
                .to_string();
            assert!(err.contains("OTEL_EXPORTER_OTLP_ENDPOINT"), "{err}");
        }
    }

    #[test]
    fn overlong_values_are_refused() {
        let long = "x".repeat(MAX_ENV_VALUE_LEN + 1);
        assert!(env(json!({"OTEL_SERVICE_NAME": long})).is_err());
        let long = "x".repeat(MAX_HEADERS_LEN + 1);
        assert!(parse(None, Some(&json!(long))).is_err());
    }

    #[test]
    fn headers_never_appear_in_debug_or_errors() {
        let t = parse(None, Some(&json!("authorization=Bearer s3cret"))).unwrap();
        assert_eq!(t.headers().unwrap().expose(), "authorization=Bearer s3cret");
        let dbg = format!("{t:?}");
        assert!(!dbg.contains("s3cret"), "{dbg}");
    }

    #[test]
    fn the_role_attribute_is_appended_to_designer_attributes() {
        let t = env(
            json!({"OTEL_RESOURCE_ATTRIBUTES": "service.namespace=prod,service.instance.id=env_1"}),
        )
        .unwrap();
        let attrs = t
            .env_for_role("router")
            .into_iter()
            .find(|(k, _)| k == "OTEL_RESOURCE_ATTRIBUTES")
            .unwrap()
            .1;
        assert_eq!(
            attrs,
            "service.namespace=prod,service.instance.id=env_1,greentic.role=router"
        );
    }

    #[test]
    fn a_headers_only_profile_still_gets_the_role_attribute() {
        let t = parse(None, Some(&json!("authorization=Bearer x"))).unwrap();
        assert!(!t.is_empty());
        assert_eq!(
            t.env_for_role("worker"),
            vec![(
                "OTEL_RESOURCE_ATTRIBUTES".to_string(),
                "greentic.role=worker".to_string()
            )]
        );
    }

    #[test]
    fn a_designer_supplied_role_is_not_duplicated() {
        let t = env(json!({"OTEL_RESOURCE_ATTRIBUTES": "greentic.role=custom"})).unwrap();
        let attrs = t
            .env_for_role("worker")
            .into_iter()
            .find(|(k, _)| k == "OTEL_RESOURCE_ATTRIBUTES")
            .unwrap()
            .1;
        assert_eq!(attrs, "greentic.role=custom");
    }
}
