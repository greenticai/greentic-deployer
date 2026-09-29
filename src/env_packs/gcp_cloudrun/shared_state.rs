//! Multi-instance safety for the Cloud Run env-pack: a Redis-backed shared
//! session/state store reached over a private VPC, and the gate that refuses
//! any multi-instance shape (`multi_instance_shape`) until every per-instance
//! hazard is closed.
//!
//! A Cloud Run instance keeps its env store in in-memory `/tmp`, re-seeded on
//! every cold start. With one instance that is merely ephemeral; with two it is
//! WRONG, three different ways, and none of them is red at any layer:
//!
//! 1. **Sessions and flow state.** greentic-runner-host keeps them in memory
//!    unless `GREENTIC_RUNNER_SESSION_BACKEND` / `GREENTIC_RUNNER_STATE_BACKEND`
//!    select Redis. A turn landing on the other instance finds no session.
//! 2. **Revision pins.** greentic-start pins a conversation to a revision in
//!    memory unless `GREENTIC_REVISION_PIN_REDIS_URL` names a Redis.
//! 3. **Generated secrets.** greentic-start's `revision_secrets` mints every
//!    declared `generated` secret (e.g. the webchat `jwt_signing_key`) at boot
//!    when the seeded dev store lacks it — PER INSTANCE. A token signed by one
//!    instance then fails verification on the next (401).
//!
//! (1) and (2) are closed by the `redis_url` answer plus a VPC route to it;
//! (3) by pre-minting every generated secret into the staged seed (the CLI's
//! `cloudrun_generated_secrets`), so boot finds them and mints nothing.
//! [`gate`] refuses a multi-instance warm unless all three hold.
//!
//! **No TLS in v1 (P5-R5).** greentic-start trusts webpki roots only, and
//! Memorystore's in-transit encryption uses a Google-private CA, so a
//! `rediss://` URL would fail its handshake at boot. It is refused here, with a
//! pointer to the follow-up (a CA-bundle answer plus custom-CA support in
//! greentic-start). Memorystore AUTH over the private VPC is what v1 ships —
//! which is also why a `redis_url` without a VPC answer is refused: the URL
//! carries the AUTH string, and without a VPC route it would cross the public
//! internet in plaintext.

use std::fmt;

use serde_json::Value;

use super::deployer::GcpCloudRunParams;

pub const REDIS_URL_KEY: &str = "redis_url";
pub const VPC_CONNECTOR_KEY: &str = "vpc_connector";
pub const VPC_NETWORK_KEY: &str = "vpc_network";
pub const VPC_SUBNET_KEY: &str = "vpc_subnet";
pub const VPC_EGRESS_KEY: &str = "vpc_egress";

/// The runner-host selectors that move sessions and flow state into Redis.
pub const SESSION_BACKEND_ENV: &str = "GREENTIC_RUNNER_SESSION_BACKEND";
pub const STATE_BACKEND_ENV: &str = "GREENTIC_RUNNER_STATE_BACKEND";
const REDIS_BACKEND: &str = "redis";

/// The two variables the Redis URL reaches the runtime through — both rendered
/// from ONE pinned Secret Manager version, never a literal in the template.
pub const REDIS_URL_ENV_NAMES: [&str; 2] = [
    "GREENTIC_RUNNER_REDIS_URL",
    "GREENTIC_REVISION_PIN_REDIS_URL",
];

/// The Redis URL (it carries the AUTH string). Never printed by `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct RedisUrl(String);

impl RedisUrl {
    /// The raw URL, for the ONE place that writes it into a secret version.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RedisUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RedisUrl(<redacted>)")
    }
}

/// Which destinations are routed through the VPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VpcEgress {
    /// Only RFC 1918 destinations (Memorystore's private IP) — the default; the
    /// runtime's public calls (LLM providers, GHCR) keep their direct route.
    #[default]
    PrivateRangesOnly,
    /// Everything, e.g. to leave through a Cloud NAT with a fixed IP.
    AllTraffic,
}

impl VpcEgress {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateRangesOnly => "private-ranges-only",
            Self::AllTraffic => "all-traffic",
        }
    }
}

/// How revisions reach the VPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpcTarget {
    /// A Serverless VPC Access connector (name or full resource path).
    Connector(String),
    /// Direct VPC egress: the network and subnetwork the instances attach to.
    Direct { network: String, subnetwork: String },
}

/// The revision's `vpcAccess` block. Revision-scoped (it lands in the
/// immutable template), so it is part of `revision_intent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpcAccess {
    pub target: VpcTarget,
    pub egress: VpcEgress,
}

/// The shared-state answers, validated. Empty by default, which renders the
/// Service and the revision intent exactly as they were before these answers
/// existed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SharedState {
    pub redis_url: Option<RedisUrl>,
    pub vpc: Option<VpcAccess>,
}

impl SharedState {
    /// Literal boot env: the two backend selectors, only when Redis is
    /// answered. The URL itself is secret-sourced ([`REDIS_URL_ENV_NAMES`]).
    pub fn boot_env(&self) -> Vec<(String, String)> {
        if self.redis_url.is_none() {
            return Vec::new();
        }
        [SESSION_BACKEND_ENV, STATE_BACKEND_ENV]
            .into_iter()
            .map(|name| (name.to_string(), REDIS_BACKEND.to_string()))
            .collect()
    }

    /// Names of the secret-sourced env vars this state adds (none when Redis is
    /// not answered).
    pub fn secret_env_names(&self) -> &'static [&'static str] {
        if self.redis_url.is_some() {
            &REDIS_URL_ENV_NAMES
        } else {
            &[]
        }
    }
}

/// Errors parsing the shared-state answers. Never carries the Redis URL: it
/// holds the AUTH string, and these messages reach logs.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SharedStateAnswerError {
    #[error("answer `{0}` must be a string")]
    NotAString(String),
    #[error(
        "answer `redis_url` uses `rediss://` (TLS), which this release refuses: greentic-start \
         trusts public web roots only and Memorystore's in-transit encryption uses a Google-private \
         CA, so the runtime would fail its TLS handshake at boot. Use Memorystore AUTH over the \
         private VPC (`redis://:<auth>@<private-ip>:6379`); TLS needs the CA-bundle answer and \
         greentic-start custom-CA support (follow-up F)"
    )]
    RedisTlsUnsupported,
    #[error("answer `redis_url` is invalid: {0}")]
    RedisUrlInvalid(String),
    #[error(
        "answer `redis_url` needs a VPC route: set `vpc_connector`, or `vpc_network` + \
         `vpc_subnet`. The URL carries the Redis AUTH string and v1 has no TLS, so it must not \
         cross the public internet"
    )]
    RedisWithoutVpc,
    #[error(
        "answers `vpc_connector` and `vpc_network`/`vpc_subnet` are alternatives; set a \
         connector OR Direct VPC egress, not both"
    )]
    VpcConnectorAndDirect,
    #[error("Direct VPC egress needs both `vpc_network` and `vpc_subnet`; `{0}` is missing")]
    VpcDirectIncomplete(&'static str),
    #[error(
        "answer `vpc_connector` is `{0}`; expected a connector name or \
         `projects/<p>/locations/<l>/connectors/<c>`"
    )]
    VpcConnectorInvalid(String),
    #[error("answer `vpc_egress` is set but no VPC is (`vpc_connector` or `vpc_network`)")]
    VpcEgressWithoutVpc,
    #[error("answer `vpc_egress` is `{0}`; expected `private-ranges-only` or `all-traffic`")]
    VpcEgressInvalid(String),
}

/// The raw shared-state answers, collected by `GcpCloudRunParams::from_answers`
/// before [`parse`] validates them together (several rules span keys).
#[derive(Debug, Default)]
pub(crate) struct RawSharedStateAnswers<'a> {
    redis_url: Option<&'a Value>,
    connector: Option<&'a Value>,
    network: Option<&'a Value>,
    subnet: Option<&'a Value>,
    egress: Option<&'a Value>,
}

impl<'a> RawSharedStateAnswers<'a> {
    /// Take `key` when it is a shared-state answer; `false` leaves it to the
    /// caller (which rejects unknown keys).
    pub(crate) fn accept(&mut self, key: &str, value: &'a Value) -> bool {
        let slot = match key {
            REDIS_URL_KEY => &mut self.redis_url,
            VPC_CONNECTOR_KEY => &mut self.connector,
            VPC_NETWORK_KEY => &mut self.network,
            VPC_SUBNET_KEY => &mut self.subnet,
            VPC_EGRESS_KEY => &mut self.egress,
            _ => return false,
        };
        *slot = Some(value);
        true
    }
}

/// A trimmed string answer; blank reads as absent (the wizard's unanswered
/// optional question).
fn optional(key: &str, value: Option<&Value>) -> Result<Option<String>, SharedStateAnswerError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let s = value
        .as_str()
        .ok_or_else(|| SharedStateAnswerError::NotAString(key.to_string()))?
        .trim();
    Ok((!s.is_empty()).then(|| s.to_string()))
}

fn parse_redis_url(raw: String) -> Result<RedisUrl, SharedStateAnswerError> {
    // Detail strings name the rule broken, never the input: it carries AUTH.
    let url = url::Url::parse(&raw)
        .map_err(|e| SharedStateAnswerError::RedisUrlInvalid(format!("not a URL ({e})")))?;
    match url.scheme() {
        "redis" => {}
        "rediss" => return Err(SharedStateAnswerError::RedisTlsUnsupported),
        _ => {
            return Err(SharedStateAnswerError::RedisUrlInvalid(
                "the scheme must be `redis://`".to_string(),
            ));
        }
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(SharedStateAnswerError::RedisUrlInvalid(
            "the URL names no host".to_string(),
        ));
    }
    Ok(RedisUrl(raw))
}

fn parse_egress(raw: &str) -> Result<VpcEgress, SharedStateAnswerError> {
    match raw {
        "private-ranges-only" => Ok(VpcEgress::PrivateRangesOnly),
        "all-traffic" => Ok(VpcEgress::AllTraffic),
        other => Err(SharedStateAnswerError::VpcEgressInvalid(other.to_string())),
    }
}

/// Validate the shared-state answers together.
/// The Cloud Run v2 `VpcAccess.connector` format is the full resource path
/// (`projects/{p}/locations/{l}/connectors/{c}`, per the v2 proto doc). A bare
/// connector name is expanded against the service's own project and region, so
/// `gtc-conn` and its full path render — and hash into the intent — the same.
/// A full path is kept verbatim (it may name a Shared-VPC host project).
fn connector_path(
    raw: String,
    project: &str,
    region: &str,
) -> Result<String, SharedStateAnswerError> {
    if !raw.contains('/') {
        return Ok(format!(
            "projects/{project}/locations/{region}/connectors/{raw}"
        ));
    }
    let parts: Vec<&str> = raw.split('/').collect();
    let well_formed = parts.len() == 6
        && parts[0] == "projects"
        && parts[2] == "locations"
        && parts[4] == "connectors"
        && [parts[1], parts[3], parts[5]].iter().all(|p| !p.is_empty());
    if well_formed {
        Ok(raw)
    } else {
        Err(SharedStateAnswerError::VpcConnectorInvalid(raw))
    }
}

pub(crate) fn parse(
    raw: RawSharedStateAnswers<'_>,
    project: &str,
    region: &str,
) -> Result<SharedState, SharedStateAnswerError> {
    let connector = optional(VPC_CONNECTOR_KEY, raw.connector)?;
    let network = optional(VPC_NETWORK_KEY, raw.network)?;
    let subnet = optional(VPC_SUBNET_KEY, raw.subnet)?;
    let egress = optional(VPC_EGRESS_KEY, raw.egress)?
        .map(|e| parse_egress(&e))
        .transpose()?;

    let target = match (connector, network, subnet) {
        (None, None, None) => None,
        (Some(connector), None, None) => Some(VpcTarget::Connector(connector_path(
            connector, project, region,
        )?)),
        (Some(_), _, _) => return Err(SharedStateAnswerError::VpcConnectorAndDirect),
        (None, Some(network), Some(subnetwork)) => Some(VpcTarget::Direct {
            network,
            subnetwork,
        }),
        (None, Some(_), None) => {
            return Err(SharedStateAnswerError::VpcDirectIncomplete(VPC_SUBNET_KEY));
        }
        (None, None, Some(_)) => {
            return Err(SharedStateAnswerError::VpcDirectIncomplete(VPC_NETWORK_KEY));
        }
    };
    let vpc = match (target, egress) {
        (Some(target), egress) => Some(VpcAccess {
            target,
            egress: egress.unwrap_or_default(),
        }),
        (None, Some(_)) => return Err(SharedStateAnswerError::VpcEgressWithoutVpc),
        (None, None) => None,
    };

    let redis_url = optional(REDIS_URL_KEY, raw.redis_url)?
        .map(parse_redis_url)
        .transpose()?;
    if redis_url.is_some() && vpc.is_none() {
        return Err(SharedStateAnswerError::RedisWithoutVpc);
    }
    Ok(SharedState { redis_url, vpc })
}

/// Whether the ANSWERS make the adapter multi-instance safe: a shared Redis
/// store and a VPC route to it. This is the adapter capability (P5-R3); the
/// per-deploy [`gate`] additionally requires the generated secrets to be
/// pre-minted into the staged seed.
pub fn multi_instance_safe(params: &GcpCloudRunParams) -> bool {
    params.shared_state.redis_url.is_some() && params.shared_state.vpc.is_some()
}

/// Whether the staged seed carries every generated secret the revision's packs
/// declare, decided by the CLI (which owns the filesystem and the dev store).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum GeneratedSecretSeed {
    /// Nobody checked — the default for a handler the CLI did not prepare. A
    /// multi-instance warm refuses on this.
    #[default]
    Unverified,
    /// Checked and could not be established, with why.
    Unestablished(String),
    /// Every generated secret was found (or pre-minted) in the staged seed.
    Complete,
    /// These store URIs are absent from the staged seed.
    Missing(Vec<String>),
}

/// How the answered scaling can run more than one instance, or `None` when it
/// is exactly one. Judged on the EFFECTIVE ceiling, not the literal answer:
///
/// - `max_instances = 0` renders an unset `maxInstanceCount`, and Cloud Run
///   then applies its own default ceiling (up to 100 instances);
/// - `min_instances > 1` keeps that many instances warm whatever the maximum.
///
/// The only single-instance shape is `max_instances == 1` with
/// `min_instances <= 1` — which is the sandbox default, so an env that answers
/// neither keeps today's behaviour byte for byte.
pub fn multi_instance_shape(params: &GcpCloudRunParams) -> Option<String> {
    if params.min_instances > 1 {
        return Some(format!("`min_instances` is {}", params.min_instances));
    }
    match params.max_instances {
        1 => None,
        0 => Some(
            "`max_instances` is 0, which Cloud Run reads as its default ceiling (up to 100 \
             instances)"
                .to_string(),
        ),
        n => Some(format!("`max_instances` is {n}")),
    }
}

/// Whether the answered scaling can run more than one instance.
pub fn runs_multiple_instances(params: &GcpCloudRunParams) -> bool {
    multi_instance_shape(params).is_some()
}

/// Why a multi-instance warm was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MultiInstanceRefusal {
    #[error(
        "{shape}, but multi-instance Cloud Run needs a shared session store: answer {missing}. \
         Without it each instance keeps its own sessions, state and revision pins in memory, \
         and a turn landing on another instance finds nothing. Set `max_instances` to 1 (and \
         `min_instances` to at most 1), or answer the missing keys"
    )]
    SharedStoreMissing { shape: String, missing: String },
    #[error(
        "{shape}, but the staged seed lacks generated secrets ({missing}); each instance would \
         mint its own at boot and tokens signed by one would fail on another"
    )]
    GeneratedSecretsMissing { shape: String, missing: String },
    #[error(
        "{shape}, but it could not be verified that every generated secret is pre-minted into \
         the staged seed: {reason}"
    )]
    GeneratedSecretsUnverified { shape: String, reason: String },
}

/// Refuse a multi-instance shape ([`multi_instance_shape`]) unless Redis + VPC
/// are answered AND the staged seed carries every generated secret. A single
/// instance always passes: it is exactly today's behaviour.
pub fn gate(
    params: &GcpCloudRunParams,
    seed: &GeneratedSecretSeed,
) -> Result<(), MultiInstanceRefusal> {
    let Some(shape) = multi_instance_shape(params) else {
        return Ok(());
    };
    if !multi_instance_safe(params) {
        let mut missing = Vec::new();
        if params.shared_state.redis_url.is_none() {
            missing.push("`redis_url`");
        }
        if params.shared_state.vpc.is_none() {
            missing.push("`vpc_connector` (or `vpc_network` + `vpc_subnet`)");
        }
        return Err(MultiInstanceRefusal::SharedStoreMissing {
            shape,
            missing: missing.join(" and "),
        });
    }
    Err(match seed {
        GeneratedSecretSeed::Complete => return Ok(()),
        GeneratedSecretSeed::Missing(uris) => MultiInstanceRefusal::GeneratedSecretsMissing {
            shape,
            missing: uris.join(", "),
        },
        GeneratedSecretSeed::Unestablished(reason) => {
            MultiInstanceRefusal::GeneratedSecretsUnverified {
                shape,
                reason: reason.clone(),
            }
        }
        GeneratedSecretSeed::Unverified => MultiInstanceRefusal::GeneratedSecretsUnverified {
            shape,
            reason: "no seed check ran for this deploy".to_string(),
        },
    })
}

#[cfg(test)]
#[path = "shared_state_tests.rs"]
mod tests;
