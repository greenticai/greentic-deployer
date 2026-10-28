//! Entra client-credentials token handling: a pure cache + response parser, and
//! the redacting credential type. The HTTP call itself lives in `reqwest_http`.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde_json::Value;

use super::arm_http::TokenScope;

/// Refresh this long before the token expires.
pub(crate) const EXPIRY_MARGIN: Duration = Duration::from_secs(120);

/// Service principal material. `Debug` never prints the secret.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ClientCredentials {
    pub tenant_id: String,
    pub client_id: String,
    secret: String,
    pub subscription_id: Option<String>,
}

impl ClientCredentials {
    pub(crate) fn new(
        tenant_id: impl Into<String>,
        client_id: impl Into<String>,
        secret: impl Into<String>,
        subscription_id: Option<String>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            client_id: client_id.into(),
            secret: secret.into(),
            subscription_id,
        }
    }

    /// For the ONE place that sends it to the token endpoint.
    pub(crate) fn expose_secret(&self) -> &str {
        &self.secret
    }

    pub(crate) fn token_url(&self) -> String {
        format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant_id
        )
    }
}

impl std::fmt::Debug for ClientCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCredentials")
            .field("tenant_id", &self.tenant_id)
            .field("client_id", &self.client_id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Parse the token endpoint's JSON into `(access_token, expires_in)`. Errors name
/// the Entra error code only, never the body.
pub(crate) fn parse_token_response(
    status: u16,
    body: &Value,
) -> Result<(String, Duration), String> {
    if !(200..300).contains(&status) {
        let code = body
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("unknown_error");
        return Err(format!("the token endpoint answered {status} ({code})"));
    }
    let token = body
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
        .ok_or("the token endpoint answered without an access_token")?;
    let secs = match body.get("expires_in") {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) => s.parse().ok(),
        _ => None,
    }
    .ok_or("the token endpoint answered without expires_in")?;
    Ok((token.to_string(), Duration::from_secs(secs)))
}

/// In-memory token cache keyed by scope.
#[derive(Default)]
pub(crate) struct TokenCache {
    entries: HashMap<TokenScope, (String, Instant)>,
}

impl std::fmt::Debug for TokenCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TokenCache({} entries)", self.entries.len())
    }
}

impl TokenCache {
    pub(crate) fn get(&self, scope: TokenScope, now: Instant) -> Option<String> {
        self.entries
            .get(&scope)
            .filter(|(_, expires)| now + EXPIRY_MARGIN < *expires)
            .map(|(t, _)| t.clone())
    }

    pub(crate) fn put(&mut self, scope: TokenScope, token: String, ttl: Duration, now: Instant) {
        self.entries.insert(scope, (token, now + ttl));
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn the_cache_returns_a_token_until_the_margin_then_refreshes() {
        let mut c = TokenCache::default();
        let t0 = Instant::now();
        assert!(c.get(TokenScope::Arm, t0).is_none());
        c.put(TokenScope::Arm, "tok".into(), Duration::from_secs(3600), t0);
        assert_eq!(
            c.get(TokenScope::Arm, t0 + Duration::from_secs(60))
                .as_deref(),
            Some("tok")
        );
        assert!(
            c.get(TokenScope::Arm, t0 + Duration::from_secs(3600 - 60))
                .is_none()
        );
    }

    #[test]
    fn parses_success_and_names_only_the_error_code_on_failure() {
        let ok = json!({"access_token": "abc", "expires_in": 3599});
        assert_eq!(
            parse_token_response(200, &ok).unwrap().1,
            Duration::from_secs(3599)
        );
        let bad = json!({"error": "invalid_client", "error_description": "secret=hunter2"});
        let e = parse_token_response(401, &bad).unwrap_err();
        assert!(
            e.contains("invalid_client") && !e.contains("hunter2"),
            "{e}"
        );
        assert!(parse_token_response(200, &json!({})).is_err());
    }

    #[test]
    fn debug_never_prints_the_client_secret() {
        let c = ClientCredentials::new("t", "c", "hunter2-secret", None);
        assert!(!format!("{c:?}").contains("hunter2-secret"));
        assert_eq!(c.expose_secret(), "hunter2-secret");
        assert!(c.token_url().contains("/t/oauth2/v2.0/token"));
    }
}
