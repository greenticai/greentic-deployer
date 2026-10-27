//! Worker scale-out for the k8s env-pack: the `replicas` answer and the shared
//! backend (`redis_url`) that must back it.
//!
//! A worker pod keeps sessions, flow state and conversation→revision pins in
//! its own memory unless the runtime is pointed at Redis. With one replica that
//! is merely ephemeral; with two, a turn landing on the other pod finds
//! nothing, and nothing is red at any layer. So `replicas > 1` is refused
//! unless `redis_url` is answered (the runtime side of that backend is
//! greenticai/greentic-start#735; this pack only renders the selectors and the
//! URL, it does not depend on that landing).
//!
//! Omitting both answers renders the worker exactly as before: `replicas: 1`,
//! no extra env, no extra Secret, no extra egress.
//!
//! Not closed here: generated secrets (e.g. the webchat signing key) are minted
//! per pod at boot when the staged dev store lacks them. The Cloud Run pack
//! pre-mints them into its seed; this pack does not (yet).

use std::fmt;

use serde_json::{Value, json};

/// Wizard answer: worker Deployment replica count.
pub const REPLICAS_KEY: &str = "replicas";
/// Wizard answer: the shared Redis the runtime keeps sessions/state/pins in.
pub const REDIS_URL_KEY: &str = "redis_url";
/// Upper bound on `replicas`; a typo guard, not a capacity claim.
pub const MAX_WORKER_REPLICAS: u32 = 20;

/// Env-level Secret carrying the Redis URL (it holds the AUTH string).
pub const SHARED_STATE_SECRET_NAME: &str = "gtc-shared-state";
const SECRET_KEY: &str = "redis-url";

const SESSION_BACKEND_ENV: &str = "GREENTIC_RUNNER_SESSION_BACKEND";
const STATE_BACKEND_ENV: &str = "GREENTIC_RUNNER_STATE_BACKEND";
/// Both variables the URL reaches the runtime through.
const REDIS_URL_ENV_NAMES: [&str; 2] = [
    "GREENTIC_RUNNER_REDIS_URL",
    "GREENTIC_REVISION_PIN_REDIS_URL",
];

/// The Redis URL. Never printed by `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct RedisUrl(String);

impl RedisUrl {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RedisUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RedisUrl(<redacted>)")
    }
}

/// Validated scale-out answers. `Default` is the pre-existing behaviour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaleOut {
    pub replicas: u32,
    pub redis_url: Option<RedisUrl>,
}

impl Default for ScaleOut {
    fn default() -> Self {
        Self {
            replicas: 1,
            redis_url: None,
        }
    }
}

fn scalar(obj: &serde_json::Map<String, Value>, key: &str) -> Result<Option<String>, String> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            let s = s.trim();
            Ok((!s.is_empty()).then(|| s.to_string()))
        }
        Some(Value::Number(n)) => Ok(Some(n.to_string())),
        Some(other) => Err(format!("{key} must be a string or number, got {other}")),
    }
}

fn parse_redis_url(raw: &str) -> Result<RedisUrl, String> {
    // Messages name the rule broken, never the input: it carries AUTH.
    let url = url::Url::parse(raw).map_err(|e| format!("redis_url is not a URL ({e})"))?;
    match url.scheme() {
        "redis" => {}
        "rediss" => {
            return Err(
                "redis_url uses `rediss://` (TLS), which this release does not support; \
                        use `redis://` on a private network"
                    .to_string(),
            );
        }
        _ => return Err("redis_url must use the `redis://` scheme".to_string()),
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err("redis_url names no host".to_string());
    }
    Ok(RedisUrl(raw.to_string()))
}

/// Parse `replicas` + `redis_url` from the binding answers and apply the gate.
pub fn parse(obj: &serde_json::Map<String, Value>) -> Result<ScaleOut, String> {
    let redis_url = scalar(obj, REDIS_URL_KEY)?
        .map(|raw| parse_redis_url(&raw))
        .transpose()?;
    let replicas = match scalar(obj, REPLICAS_KEY)? {
        None => 1,
        Some(s) => s
            .parse::<u32>()
            .map_err(|e| format!("replicas `{s}` is not a valid u32: {e}"))?,
    };
    if replicas < 1 {
        return Err("replicas must be >= 1, got 0".to_string());
    }
    if replicas > MAX_WORKER_REPLICAS {
        return Err(format!(
            "replicas must be <= {MAX_WORKER_REPLICAS}, got {replicas}"
        ));
    }
    if replicas > 1 && redis_url.is_none() {
        return Err(format!(
            "replicas is {replicas}, but more than one worker replica needs a shared session \
             store: answer `redis_url`. Without it each pod keeps its own sessions, flow state \
             and revision pins in memory, and a turn landing on another pod finds nothing \
             (shared backend in the runtime: greenticai/greentic-start#735). Set `replicas` \
             to 1, or answer `redis_url`"
        ));
    }
    Ok(ScaleOut {
        replicas,
        redis_url,
    })
}

impl ScaleOut {
    /// Worker env: the two backend selectors plus the URL by `secretKeyRef`.
    /// Empty unless `redis_url` is answered.
    pub fn worker_env(&self) -> Vec<Value> {
        if self.redis_url.is_none() {
            return Vec::new();
        }
        let mut vars: Vec<Value> = [SESSION_BACKEND_ENV, STATE_BACKEND_ENV]
            .into_iter()
            .map(|n| json!({"name": n, "value": "redis"}))
            .collect();
        vars.extend(REDIS_URL_ENV_NAMES.into_iter().map(|n| {
            json!({
                "name": n,
                "valueFrom": {"secretKeyRef": {
                    "name": SHARED_STATE_SECRET_NAME,
                    "key": SECRET_KEY,
                }},
            })
        }));
        vars
    }

    /// The env-level Secret holding the URL, when answered.
    pub fn render_secret(&self, namespace: &str, labels: Value) -> Option<Value> {
        let url = self.redis_url.as_ref()?;
        Some(json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "type": "Opaque",
            "metadata": {
                "name": SHARED_STATE_SECRET_NAME,
                "namespace": namespace,
                "labels": labels,
            },
            "stringData": {SECRET_KEY: url.expose()},
        }))
    }

    /// Whether workers need egress to reach the shared store.
    pub fn needs_egress(&self) -> bool {
        self.redis_url.is_some()
    }
}

#[cfg(test)]
#[path = "scale_out_tests.rs"]
mod tests;
