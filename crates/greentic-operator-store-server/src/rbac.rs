//! Static bearer-token RBAC for the operator store server (A8 #3, PR-4.4).
//!
//! Two postures, chosen at startup:
//!
//! - **Open-dev** (no token file configured): every request is allowed and
//!   audited as the honest `Allow{policy: "open-dev"}` — the pre-PR-4.4
//!   behavior, intended for loopback development. The binary refuses
//!   non-loopback binds in this posture unless the insecure escape hatch
//!   is set.
//! - **Static tokens** (`--rbac-tokens <file>`): every request must carry
//!   `Authorization: Bearer <token>`; the token's SHA-256 is looked up in
//!   the configured map and yields a named actor + role. Missing or
//!   unrecognized tokens, and authenticated actors whose role does not
//!   permit the verb, are denied with the A8 `403 unauthorized` body —
//!   and denied MUTATIONS are still written to the durable audit log
//!   (contract #3: "the rejected attempt is still audited").
//!
//! The token file stores SHA-256 digests, never plaintext tokens, so the
//! config file is not itself a secret store. Lookup hashes the presented
//! token and compares digests — a timing difference can only leak digest
//! prefixes, which do not help reconstruct a token (preimage resistance).
//!
//! Roles are deliberately coarse (the production policy engine can replace
//! this module while keeping the `AuditDecision` shape, per the contract):
//!
//! | Role | Reads | Mutations |
//! |------|-------|-----------|
//! | `admin` | all | all |
//! | `operator` | all | all except `trust-root` writes (key custody — deciding WHO may sign revenue policies — stays admin-only) |
//! | `read-only` | all | none |

use std::collections::HashMap;
use std::path::Path;

use greentic_deploy_spec::{Actor, AuditDecision, EnvId};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Policy name recorded on every decision while RBAC is not configured.
/// Honest about what it is — every request is allowed.
pub const POLICY_OPEN_DEV: &str = "open-dev";
/// Policy name recorded on every decision made by the static token map.
pub const POLICY_STATIC_TOKENS: &str = "static-tokens";
/// Schema discriminator the token file must carry.
pub const RBAC_TOKENS_SCHEMA_V1: &str = "greentic.store-rbac.v1";

/// Coarse role granted to a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    Admin,
    Operator,
    ReadOnly,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Operator => "operator",
            Role::ReadOnly => "read-only",
        }
    }

    /// May this role apply the mutation `noun.verb`? Reads are not gated
    /// per-role (any authenticated actor may read).
    fn allows_mutation(self, noun: &str) -> bool {
        match self {
            Role::Admin => true,
            // Trust-root writes are key custody — they decide WHO is
            // trusted to sign revenue policies. Day-to-day deploy ops
            // (env, revisions, traffic, bindings, bundles, messaging,
            // backups) stay open to operators.
            Role::Operator => noun != "trust-root",
            Role::ReadOnly => false,
        }
    }
}

/// Environment scope for a token: either unrestricted (all environments)
/// or restricted to an explicit set.
#[derive(Debug, Clone)]
pub enum EnvScope {
    /// The token may access any environment.
    All,
    /// The token may only access environments whose id appears in the set.
    Restricted(Vec<EnvId>),
}

impl EnvScope {
    /// Does this scope grant access to `env_id`?
    pub fn permits(&self, env_id: &EnvId) -> bool {
        match self {
            EnvScope::All => true,
            EnvScope::Restricted(ids) => ids.iter().any(|id| id == env_id),
        }
    }
}

/// One configured principal: the authenticated identity behind a token.
#[derive(Debug, Clone)]
struct Principal {
    actor: String,
    role: Role,
    scope: EnvScope,
}

/// On-disk token file shape (`--rbac-tokens`).
#[derive(Debug, Deserialize)]
struct TokenFile {
    schema: String,
    tokens: Vec<TokenEntry>,
}

#[derive(Debug, Deserialize)]
struct TokenEntry {
    /// Lowercase-hex SHA-256 of the bearer token (64 chars).
    token_sha256: String,
    /// Actor name recorded in audit events (`Actor.user`).
    actor: String,
    role: Role,
    /// Optional environment scope: when present, the token may only access
    /// the listed environment ids; absent or `null` means "all envs".
    #[serde(default)]
    env_ids: Option<Vec<String>>,
}

/// Why the token file was rejected at startup. Startup-only — never a
/// per-request error.
#[derive(Debug, Error)]
pub enum RbacConfigError {
    #[error("cannot read RBAC token file `{path}`: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("cannot parse RBAC token file `{path}`: {source}")]
    Parse {
        path: String,
        source: serde_json::Error,
    },
    #[error("RBAC token file schema is `{found}`, expected `{RBAC_TOKENS_SCHEMA_V1}`")]
    Schema { found: String },
    #[error(
        "RBAC token file declares no tokens — a configured-but-empty file would deny everything; remove the flag for open-dev instead"
    )]
    Empty,
    #[error("token entry {index}: `token_sha256` must be 64 lowercase hex chars")]
    BadDigest { index: usize },
    #[error("token entry {index}: `actor` must not be empty")]
    EmptyActor { index: usize },
    #[error("token entry {index}: duplicate `token_sha256`")]
    DuplicateDigest { index: usize },
    #[error(
        "token entry {index}: `env_ids` is present but empty (omit the field for all-env access)"
    )]
    EmptyEnvIds { index: usize },
    #[error("token entry {index}: invalid env id `{env_id}`: {reason}")]
    InvalidEnvId {
        index: usize,
        env_id: String,
        reason: String,
    },
}

/// The outcome of authenticating + authorizing one request.
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Who acted — recorded verbatim in the audit event.
    pub actor: Actor,
    /// The Allow decision — recorded verbatim in the audit event.
    pub decision: AuditDecision,
}

/// A denied request: the actor (possibly anonymous) and the Deny decision,
/// both destined for the durable denial audit row.
#[derive(Debug, Clone)]
pub struct RbacDenial {
    pub actor: Actor,
    pub policy: String,
    pub reason: String,
    /// `true` when the token was recognized (the denial is a role/scope
    /// check, not a missing-token rejection). Callers gate durable audit
    /// persistence on this: anonymous denials are logged but not persisted.
    pub authenticated: bool,
}

/// The server's authorization engine. Cheap to share (`Arc` in `AppState`).
#[derive(Debug)]
pub struct RbacEngine(Posture);

#[derive(Debug)]
enum Posture {
    /// No tokens configured: allow everything (dev/loopback posture).
    OpenDev,
    /// Static token map: fail closed.
    StaticTokens {
        principals: HashMap<String, Principal>,
    },
}

impl RbacEngine {
    /// The allow-all posture used when no token file is configured.
    pub fn open_dev() -> Self {
        Self(Posture::OpenDev)
    }

    /// Load and validate a token file. Fails fast at startup — a malformed
    /// policy must never silently degrade to open-dev.
    pub fn from_token_file(path: &Path) -> Result<Self, RbacConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|source| RbacConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let file: TokenFile =
            serde_json::from_str(&raw).map_err(|source| RbacConfigError::Parse {
                path: path.display().to_string(),
                source,
            })?;
        if file.schema != RBAC_TOKENS_SCHEMA_V1 {
            return Err(RbacConfigError::Schema { found: file.schema });
        }
        if file.tokens.is_empty() {
            return Err(RbacConfigError::Empty);
        }
        let mut principals = HashMap::with_capacity(file.tokens.len());
        for (index, entry) in file.tokens.into_iter().enumerate() {
            let digest = entry.token_sha256.to_ascii_lowercase();
            if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(RbacConfigError::BadDigest { index });
            }
            if entry.actor.trim().is_empty() {
                return Err(RbacConfigError::EmptyActor { index });
            }
            let scope = match entry.env_ids {
                None => EnvScope::All,
                Some(ref ids) if ids.is_empty() => {
                    return Err(RbacConfigError::EmptyEnvIds { index });
                }
                Some(ids) => {
                    let mut parsed = Vec::with_capacity(ids.len());
                    for raw in &ids {
                        let env_id = EnvId::try_from(raw.as_str()).map_err(|err| {
                            RbacConfigError::InvalidEnvId {
                                index,
                                env_id: raw.clone(),
                                reason: err.to_string(),
                            }
                        })?;
                        parsed.push(env_id);
                    }
                    EnvScope::Restricted(parsed)
                }
            };
            let clash = principals.insert(
                digest,
                Principal {
                    actor: entry.actor,
                    role: entry.role,
                    scope,
                },
            );
            if clash.is_some() {
                return Err(RbacConfigError::DuplicateDigest { index });
            }
        }
        Ok(Self(Posture::StaticTokens { principals }))
    }

    /// True when a static token map is enforced (drives the binary's
    /// non-loopback bind gate).
    pub fn is_enforcing(&self) -> bool {
        matches!(self.0, Posture::StaticTokens { .. })
    }

    /// Authenticate the request's bearer token. `Ok` carries the principal
    /// (named actor + role + env scope); `Err` carries the anonymous denial.
    fn authenticate(
        &self,
        bearer_token: Option<&str>,
    ) -> Result<(Actor, Role, EnvScope), RbacDenial> {
        let Posture::StaticTokens { principals } = &self.0 else {
            // Open-dev: anonymous admin-equivalent. Actor kind matches the
            // pre-PR-4.4 audit shape.
            return Ok((
                Actor {
                    kind: "store-server".to_string(),
                    user: None,
                    uid: None,
                },
                Role::Admin,
                EnvScope::All,
            ));
        };
        let denied = || RbacDenial {
            actor: Actor {
                kind: "anonymous".to_string(),
                user: None,
                uid: None,
            },
            policy: POLICY_STATIC_TOKENS.to_string(),
            reason: "missing or unrecognized bearer token".to_string(),
            authenticated: false,
        };
        let token = bearer_token.ok_or_else(denied)?;
        let digest = hex::encode(Sha256::digest(token.as_bytes()));
        let principal = principals.get(&digest).ok_or_else(denied)?;
        Ok((
            Actor {
                kind: "bearer-token".to_string(),
                user: Some(principal.actor.clone()),
                uid: None,
            },
            principal.role,
            principal.scope.clone(),
        ))
    }

    /// Authorize a MUTATION (`noun.verb`) on `env_id`. The returned
    /// [`AuthContext`] carries the Allow decision destined for the mutation's
    /// audit event; a denial carries the actor + Deny material for the
    /// durable denial audit row the caller must write.
    pub fn authorize_mutation(
        &self,
        bearer_token: Option<&str>,
        env_id: &EnvId,
        noun: &str,
        verb: &str,
    ) -> Result<AuthContext, RbacDenial> {
        let (actor, role, scope) = self.authenticate(bearer_token)?;
        if let Posture::OpenDev = self.0 {
            return Ok(AuthContext {
                actor,
                decision: AuditDecision::Allow {
                    policy: POLICY_OPEN_DEV.to_string(),
                    reason: "RBAC tokens not configured; open-dev allows all".to_string(),
                },
            });
        }
        if !scope.permits(env_id) {
            return Err(RbacDenial {
                policy: POLICY_STATIC_TOKENS.to_string(),
                reason: format!(
                    "token is not scoped for environment `{env_id}` on `{noun}.{verb}`"
                ),
                actor,
                authenticated: true,
            });
        }
        if role.allows_mutation(noun) {
            Ok(AuthContext {
                actor,
                decision: AuditDecision::Allow {
                    policy: POLICY_STATIC_TOKENS.to_string(),
                    reason: format!("role `{}` permits `{noun}.{verb}`", role.as_str()),
                },
            })
        } else {
            Err(RbacDenial {
                policy: POLICY_STATIC_TOKENS.to_string(),
                reason: format!("role `{}` does not permit `{noun}.{verb}`", role.as_str()),
                actor,
                authenticated: true,
            })
        }
    }

    /// Authorize a READ on a specific environment: any authenticated actor
    /// whose scope includes `env_id`. `env_id` is `None` for collection
    /// reads (e.g. `GET /environments`) where filtering happens post-auth
    /// via [`Self::read_scope`].
    pub fn authorize_read(
        &self,
        bearer_token: Option<&str>,
        env_id: Option<&EnvId>,
    ) -> Result<(), RbacDenial> {
        let (_actor, _role, scope) = self.authenticate(bearer_token)?;
        if let Some(id) = env_id
            && !scope.permits(id)
        {
            return Err(RbacDenial {
                actor: _actor,
                policy: POLICY_STATIC_TOKENS.to_string(),
                reason: format!("token is not scoped for environment `{id}`"),
                authenticated: true,
            });
        }
        Ok(())
    }

    /// Return the environment scope for a bearer token, so callers can
    /// filter collection reads (e.g. `GET /environments`). Returns
    /// `EnvScope::All` for open-dev and all-env tokens.
    pub fn read_scope(&self, bearer_token: Option<&str>) -> Result<EnvScope, RbacDenial> {
        let (_actor, _role, scope) = self.authenticate(bearer_token)?;
        Ok(scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256_hex(token: &str) -> String {
        hex::encode(Sha256::digest(token.as_bytes()))
    }

    fn engine_with(entries: &[(&str, &str, &str)]) -> RbacEngine {
        let tokens: Vec<serde_json::Value> = entries
            .iter()
            .map(|(token, actor, role)| {
                serde_json::json!({
                    "token_sha256": sha256_hex(token),
                    "actor": actor,
                    "role": role,
                })
            })
            .collect();
        let file = serde_json::json!({
            "schema": RBAC_TOKENS_SCHEMA_V1,
            "tokens": tokens,
        });
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        RbacEngine::from_token_file(&path).expect("valid token file")
    }

    fn test_env_id() -> EnvId {
        EnvId::try_from("local").expect("valid env id")
    }

    #[test]
    fn open_dev_allows_everything_with_the_honest_policy() {
        let engine = RbacEngine::open_dev();
        let id = test_env_id();
        let ctx = engine
            .authorize_mutation(None, &id, "trust-root", "bootstrap")
            .expect("open-dev allows");
        assert_eq!(ctx.actor.kind, "store-server");
        match ctx.decision {
            AuditDecision::Allow { policy, .. } => assert_eq!(policy, POLICY_OPEN_DEV),
            AuditDecision::Deny { .. } => panic!("open-dev must allow"),
        }
        engine.authorize_read(None, None).expect("open-dev reads");
        assert!(!engine.is_enforcing());
    }

    #[test]
    fn missing_and_unknown_tokens_are_anonymous_denials() {
        let engine = engine_with(&[("s3cret", "alice", "admin")]);
        let id = test_env_id();
        assert!(engine.is_enforcing());
        for token in [None, Some("wrong")] {
            let denial = engine
                .authorize_mutation(token, &id, "env", "update")
                .expect_err("must deny");
            assert_eq!(denial.actor.kind, "anonymous");
            assert_eq!(denial.policy, POLICY_STATIC_TOKENS);
            assert!(denial.reason.contains("bearer token"));
            assert!(!denial.authenticated);
            engine
                .authorize_read(token, None)
                .expect_err("reads gated too");
        }
    }

    #[test]
    fn role_matrix_governs_mutations() {
        let engine = engine_with(&[
            ("admin-tok", "root", "admin"),
            ("op-tok", "deployer", "operator"),
            ("ro-tok", "viewer", "read-only"),
        ]);
        let id = test_env_id();
        // Admin: everything, including key custody.
        engine
            .authorize_mutation(Some("admin-tok"), &id, "trust-root", "bootstrap")
            .expect("admin may manage trust root");
        // Operator: deploy ops yes, key custody no.
        let ctx = engine
            .authorize_mutation(Some("op-tok"), &id, "env", "update")
            .expect("operator may deploy");
        assert_eq!(ctx.actor.user.as_deref(), Some("deployer"));
        let denial = engine
            .authorize_mutation(Some("op-tok"), &id, "trust-root", "keys.add")
            .expect_err("operator must not manage trust root");
        assert!(denial.reason.contains("operator"));
        assert_eq!(denial.actor.user.as_deref(), Some("deployer"));
        assert!(denial.authenticated);
        // Read-only: reads yes, mutations no.
        engine
            .authorize_read(Some("ro-tok"), None)
            .expect("read-only may read");
        engine
            .authorize_mutation(Some("ro-tok"), &id, "traffic", "set")
            .expect_err("read-only must not mutate");
    }

    #[test]
    fn token_file_validation_fails_fast() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        let write =
            |v: serde_json::Value| std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();

        write(serde_json::json!({"schema": "wrong.v1", "tokens": []}));
        assert!(matches!(
            RbacEngine::from_token_file(&path),
            Err(RbacConfigError::Schema { .. })
        ));

        write(serde_json::json!({"schema": RBAC_TOKENS_SCHEMA_V1, "tokens": []}));
        assert!(matches!(
            RbacEngine::from_token_file(&path),
            Err(RbacConfigError::Empty)
        ));

        write(
            serde_json::json!({"schema": RBAC_TOKENS_SCHEMA_V1, "tokens": [
                {"token_sha256": "nothex", "actor": "a", "role": "admin"}
            ]}),
        );
        assert!(matches!(
            RbacEngine::from_token_file(&path),
            Err(RbacConfigError::BadDigest { index: 0 })
        ));

        let digest = sha256_hex("tok");
        write(
            serde_json::json!({"schema": RBAC_TOKENS_SCHEMA_V1, "tokens": [
                {"token_sha256": digest, "actor": "  ", "role": "admin"}
            ]}),
        );
        assert!(matches!(
            RbacEngine::from_token_file(&path),
            Err(RbacConfigError::EmptyActor { index: 0 })
        ));

        write(
            serde_json::json!({"schema": RBAC_TOKENS_SCHEMA_V1, "tokens": [
                {"token_sha256": digest, "actor": "a", "role": "admin"},
                {"token_sha256": digest.to_ascii_uppercase(), "actor": "b", "role": "operator"}
            ]}),
        );
        assert!(matches!(
            RbacEngine::from_token_file(&path),
            Err(RbacConfigError::DuplicateDigest { index: 1 })
        ));

        write(
            serde_json::json!({"schema": RBAC_TOKENS_SCHEMA_V1, "tokens": [
                {"token_sha256": digest, "actor": "a", "role": "superuser"}
            ]}),
        );
        assert!(matches!(
            RbacEngine::from_token_file(&path),
            Err(RbacConfigError::Parse { .. })
        ));
    }

    #[test]
    fn digest_lookup_is_case_insensitive_on_the_config_side() {
        // The file may carry uppercase hex; the presented token still maps.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "schema": RBAC_TOKENS_SCHEMA_V1,
                "tokens": [{
                    "token_sha256": sha256_hex("tok").to_ascii_uppercase(),
                    "actor": "a",
                    "role": "admin",
                }],
            }))
            .unwrap(),
        )
        .unwrap();
        let engine = RbacEngine::from_token_file(&path).expect("valid");
        let id = test_env_id();
        engine
            .authorize_mutation(Some("tok"), &id, "env", "create")
            .expect("uppercase digest still matches");
    }

    #[test]
    fn env_scoped_token_restricts_access() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "schema": RBAC_TOKENS_SCHEMA_V1,
                "tokens": [{
                    "token_sha256": sha256_hex("scoped-tok"),
                    "actor": "scoped-user",
                    "role": "admin",
                    "env_ids": ["staging"],
                }],
            }))
            .unwrap(),
        )
        .unwrap();
        let engine = RbacEngine::from_token_file(&path).expect("valid");
        let staging = EnvId::try_from("staging").expect("valid");
        let prod = EnvId::try_from("prod").expect("valid");

        // Mutations on the scoped env succeed.
        engine
            .authorize_mutation(Some("scoped-tok"), &staging, "env", "create")
            .expect("scoped token may access staging");

        // Mutations on a different env are denied (authenticated denial).
        let denial = engine
            .authorize_mutation(Some("scoped-tok"), &prod, "env", "create")
            .expect_err("scoped token must not access prod");
        assert!(denial.authenticated);
        assert!(denial.reason.contains("not scoped"));

        // Reads on the scoped env succeed; others are denied.
        engine
            .authorize_read(Some("scoped-tok"), Some(&staging))
            .expect("scoped read on staging");
        engine
            .authorize_read(Some("scoped-tok"), Some(&prod))
            .expect_err("scoped read on prod must deny");

        // Collection read (None env_id) succeeds — filtering is the caller's job.
        engine
            .authorize_read(Some("scoped-tok"), None)
            .expect("collection read always passes auth");

        // read_scope returns the restriction.
        let scope = engine.read_scope(Some("scoped-tok")).expect("read_scope");
        assert!(scope.permits(&staging));
        assert!(!scope.permits(&prod));
    }

    #[test]
    fn empty_env_ids_is_rejected_at_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "schema": RBAC_TOKENS_SCHEMA_V1,
                "tokens": [{
                    "token_sha256": sha256_hex("tok"),
                    "actor": "a",
                    "role": "admin",
                    "env_ids": [],
                }],
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            RbacEngine::from_token_file(&path),
            Err(RbacConfigError::EmptyEnvIds { index: 0 })
        ));
    }

    #[test]
    fn invalid_env_id_in_scope_is_rejected_at_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "schema": RBAC_TOKENS_SCHEMA_V1,
                "tokens": [{
                    "token_sha256": sha256_hex("tok"),
                    "actor": "a",
                    "role": "admin",
                    "env_ids": ["valid", "INVALID ID WITH SPACES"],
                }],
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            RbacEngine::from_token_file(&path),
            Err(RbacConfigError::InvalidEnvId { index: 0, .. })
        ));
    }
}
