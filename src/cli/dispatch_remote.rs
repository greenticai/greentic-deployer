//! Remote-store dispatch for `gtc op …` (PR-3c).
//!
//! When `--store-url` (or `GREENTIC_STORE_URL`) is set and `--schema` is NOT,
//! mutation verbs run end-to-end over HTTP through
//! [`EnvironmentMutations`](crate::environment::EnvironmentMutations).
//!
//! Read-only / local-only verbs return
//! [`OpError::NotYetImplemented`](super::OpError::NotYetImplemented).
//! Blocked mutation verbs (those that need a local read or local side-effect
//! the HTTP store does not yet provide) also return `NotYetImplemented` with
//! a clear message.
//!
//! `env apply` is the one composite verb: `remote_env_apply` reads a
//! `greentic.env-manifest.v1` document and reconciles the whole env against
//! the remote store by composing the typed verbs above (env update,
//! trust-root, bindings, bundle add, revision stage/warm, traffic, messaging),
//! fail-closing on the sections a control-plane store cannot own.

use greentic_deploy_spec::{
    BundleId, DeploymentId, EnvId, EnvironmentHostConfig, IdempotencyKey, MessagingEndpointId,
    PackId, RevenueShareEntry, RevisionId, SetTrafficSplitPayload, StageRevisionPayload,
    TrafficSplitEntry, WarmRevisionPayload,
};
use serde_json::{Value, json};

use crate::environment::{
    AddBundlePayload, AddMessagingEndpointPayload, AuthMethod, EnvironmentMutations, FieldUpdate,
    HttpEnvironmentStore, RemoveBundleOutcome, SetMessagingWelcomeFlowPayload, StoreError,
    UpdateBundlePayload, UpdateEnvironmentPayload,
};

use super::dispatch::{
    BundlesVerb, ConfigVerb, CredentialsVerb, EnvPacksVerb, EnvVerb, ExtensionsVerb,
    MessagingEndpointVerb, MessagingNoun, OpCommand, OpNoun, RevisionsVerb, SecretsVerb,
    TrafficVerb, TrustRootVerb, UpdatesVerb, print_outcome,
};
use super::env_apply::{ApplyMode, ApplyOptions};
use super::env_manifest::{EnvManifest, ManifestBundle};
use super::{OpError, OpFlags, OpOutcome, map_store_err_preserving_noun};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Resolve the remote store target `(url, token)`, pairing them by ORIGIN so
/// an env-configured token can never leak to an ad-hoc `--store-url` flag
/// endpoint.
///
/// - URL from `--store-url` (flag) → token must also be explicit
///   (`--store-token`); the env token is NOT inherited, because its origin
///   doesn't match the flag URL.
/// - URL from `GREENTIC_STORE_URL` (env) → token may come from `--store-token`
///   (flag wins) or `GREENTIC_STORE_TOKEN` (env) — both are "configured", so
///   the origins are consistent.
/// - No URL from either source → no remote target.
pub(crate) fn resolve_remote_target(
    flag_url: Option<String>,
    flag_token: Option<String>,
    env_url: Option<String>,
    env_token: Option<String>,
) -> (Option<String>, Option<String>) {
    match flag_url {
        Some(url) => (Some(url), flag_token),
        None => match env_url {
            Some(url) => (Some(url), flag_token.or(env_token)),
            None => (None, None),
        },
    }
}

/// Dispatch an `OpCommand` against a remote HTTP store.
///
/// Called from [`super::dispatch::dispatch_op_with_registry`] when
/// `--store-url` / `GREENTIC_STORE_URL` is set and `--schema` is false.
pub(crate) fn dispatch_op_remote(
    raw_url: &str,
    token: Option<String>,
    cmd: OpCommand,
    flags: &OpFlags,
) -> Result<(), OpError> {
    let url = url::Url::parse(raw_url)
        .map_err(|e| OpError::InvalidArgument(format!("--store-url: {e}")))?;
    let auth = match token {
        Some(t) => AuthMethod::Bearer(t),
        None => AuthMethod::None,
    };
    let store = HttpEnvironmentStore::new(url, auth)
        .map_err(|e| OpError::InvalidArgument(format!("remote store: {e}")))?;
    let outcome = route_remote(&store, flags, cmd.noun)?;
    print_outcome(&outcome)
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

// Takes the concrete `HttpEnvironmentStore` (not `&dyn EnvironmentMutations`)
// so it can hand the store to BOTH the mutation helpers (`&dyn
// EnvironmentMutations`) and the shared read verbs (`&dyn EnvironmentReads`)
// by coercion — trait objects can't cross-cast between the two.
fn route_remote(
    store: &HttpEnvironmentStore,
    flags: &OpFlags,
    noun: OpNoun,
) -> Result<OpOutcome, OpError> {
    match noun {
        // -- env ---------------------------------------------------------------
        OpNoun::Env { verb } => match verb {
            EnvVerb::Create(args) => {
                let payload = args.into_payload("create", flags)?;
                remote_env_create(store, flags, payload)
            }
            EnvVerb::Update(args) => {
                let payload = args.into_payload("update", flags)?;
                remote_env_update(store, flags, payload)
            }
            EnvVerb::SetPublicUrl(args) => {
                remote_env_set_public_url(store, &args.env_id, &args.url)
            }
            EnvVerb::Init(_) => Err(not_supported("env init")),
            EnvVerb::Up(_) => Err(not_supported("env up")),
            // Manifest-driven whole-env document reconcile over the remote
            // store. `--emit-answers-template` is store-independent (a local
            // template write), so it runs the same as on the local path.
            EnvVerb::Apply(mut args) => {
                if let Some(path) = args.emit_answers_template.take() {
                    super::env_apply::emit_answers_template(&path)
                } else {
                    remote_env_apply(store, flags, args.into_options())
                }
            }
            EnvVerb::List => super::env::list(store, flags),
            EnvVerb::Show { env_id } => super::env::show(store, flags, &env_id),
            EnvVerb::Doctor { .. } => Err(not_supported("env doctor")),
            EnvVerb::ToolCheck { .. } => Err(not_supported("env tool-check")),
            EnvVerb::Render(_) => Err(not_supported("env render")),
            EnvVerb::Reconcile(args) => remote_reconcile(store, flags, args),
            EnvVerb::ApplyRevision(_) => Err(not_supported("env apply-revision")),
            EnvVerb::ApplyTraffic(_) => Err(not_supported("env apply-traffic")),
            EnvVerb::Destroy { .. } => Err(not_supported("env destroy")),
            EnvVerb::MigrateDev { .. } => Err(not_supported("env migrate-dev")),
            EnvVerb::MigrateState { .. } => Err(not_supported("env migrate-state")),
        },

        // -- env-packs ---------------------------------------------------------
        OpNoun::EnvPacks { verb } => match verb {
            EnvPacksVerb::Add => remote_env_packs_add(store, flags),
            EnvPacksVerb::Update => remote_env_packs_update(store, flags),
            EnvPacksVerb::Remove => remote_env_packs_remove(store, flags),
            EnvPacksVerb::Rollback => remote_env_packs_rollback(store, flags),
            EnvPacksVerb::List { env_id } => super::env_packs::list(store, flags, &env_id),
        },

        // -- extensions --------------------------------------------------------
        OpNoun::Extensions { verb } => match verb {
            ExtensionsVerb::Add => remote_extensions_add(store, flags),
            ExtensionsVerb::Update => remote_extensions_update(store, flags),
            ExtensionsVerb::Remove => remote_extensions_remove(store, flags),
            ExtensionsVerb::Rollback => remote_extensions_rollback(store, flags),
            ExtensionsVerb::List { env_id } => super::extensions::list(store, flags, &env_id),
        },

        // -- bundles -----------------------------------------------------------
        OpNoun::Bundles { verb } => match verb {
            BundlesVerb::Add => remote_bundles_add(store, flags),
            BundlesVerb::Update => remote_bundles_update(store, flags),
            BundlesVerb::Remove => remote_bundles_remove(store, flags),
            BundlesVerb::List { env_id } => super::bundles::list(store, flags, &env_id),
        },

        // -- traffic -----------------------------------------------------------
        OpNoun::Traffic { verb } => match verb {
            TrafficVerb::Set(args) => {
                let payload = super::traffic::payload_from_set_args(args)?;
                remote_traffic_set(store, flags, payload)
            }
            TrafficVerb::Show(args) => {
                let payload = super::traffic::payload_from_target_args(args)?;
                super::traffic::show(store, flags, payload)
            }
            TrafficVerb::Rollback(args) => {
                let payload = super::traffic::payload_from_target_args(args)?;
                remote_traffic_rollback(store, flags, payload)
            }
        },

        // -- revisions ---------------------------------------------------------
        OpNoun::Revisions { verb } => match verb {
            RevisionsVerb::Drain => {
                remote_revision_transition(store, flags, "drain", |s, e, r, k| {
                    s.drain_revision(e, r, k)
                })
            }
            RevisionsVerb::Archive => {
                remote_revision_transition(store, flags, "archive", |s, e, r, k| {
                    s.archive_revision(e, r, k)
                })
            }
            RevisionsVerb::Stage(args) => remote_revision_stage(store, flags, args),
            RevisionsVerb::Warm => remote_revision_warm(store, flags),
            RevisionsVerb::List { env_id } => super::revisions::list(store, flags, &env_id),
        },

        // -- messaging ---------------------------------------------------------
        OpNoun::Messaging { verb } => match verb {
            MessagingNoun::Endpoint { verb } => match verb {
                MessagingEndpointVerb::Add(args) => {
                    let payload = args.into_payload("add", flags)?;
                    remote_messaging_add(store, flags, payload)
                }
                MessagingEndpointVerb::LinkBundle(args) => {
                    let payload = args.into_payload("link-bundle", flags)?;
                    remote_messaging_link_bundle(store, flags, payload)
                }
                MessagingEndpointVerb::UnlinkBundle(args) => {
                    let payload = args.into_payload("unlink-bundle", flags)?;
                    remote_messaging_unlink_bundle(store, flags, payload)
                }
                MessagingEndpointVerb::SetWelcomeFlow(args) => {
                    let payload = args.into_payload("set-welcome-flow", flags)?;
                    remote_messaging_set_welcome_flow(store, flags, payload)
                }
                MessagingEndpointVerb::Remove(args) => {
                    let payload = args.into_remove_payload("remove", flags)?;
                    remote_messaging_remove(store, flags, payload)
                }
                MessagingEndpointVerb::RotateWebhookSecret(args) => {
                    // The route exists since PR-4.2h. The server records a
                    // rotation that carries a NEW caller-supplied
                    // `webhook_secret_ref` (supplied via `--answers`) and
                    // refuses a no-ref rotation with 501 — the capability
                    // knowledge lives server-side, not in a CLI guard. The
                    // inline-flag form carries no ref (so it stays refless).
                    let payload = args.into_rotate_payload("rotate-webhook-secret", flags)?;
                    remote_messaging_rotate(store, flags, payload)
                }
                MessagingEndpointVerb::List { env_id } => {
                    super::messaging::list(store, flags, &env_id)
                }
                MessagingEndpointVerb::Show {
                    env_id,
                    endpoint_id,
                } => super::messaging::show(store, flags, &env_id, &endpoint_id),
            },
        },

        // -- trust-root --------------------------------------------------------
        OpNoun::TrustRoot { verb } => match verb {
            TrustRootVerb::Bootstrap { env_id } => {
                remote_trust_root_bootstrap(store, flags, env_id)
            }
            TrustRootVerb::Add(args) => remote_trust_root_add(store, flags, args),
            TrustRootVerb::Remove(args) => remote_trust_root_remove(store, flags, args),
            TrustRootVerb::List { env_id } => remote_trust_root_list(store, &env_id),
        },

        // -- deploy (composite rollout over the remote store) ------------------
        OpNoun::Deploy(args) => {
            remote_deploy(store, flags, super::deploy::payload_from_deploy_args(args)?)
        }

        // -- local-only nouns --------------------------------------------------
        OpNoun::Config { verb } => match verb {
            ConfigVerb::Show => Err(not_supported("config show")),
            ConfigVerb::Set => Err(not_supported("config set")),
        },
        OpNoun::Credentials { verb } => match verb {
            CredentialsVerb::Requirements => Err(not_supported("credentials requirements")),
            CredentialsVerb::Bootstrap => Err(not_supported("credentials bootstrap")),
            CredentialsVerb::Rotate => Err(not_supported("credentials rotate")),
        },
        OpNoun::Secrets { verb } => match verb {
            SecretsVerb::List => Err(not_supported("secrets list")),
            SecretsVerb::Put => Err(not_supported("secrets put")),
            SecretsVerb::Get => Err(not_supported("secrets get")),
            SecretsVerb::Rotate => Err(not_supported("secrets rotate")),
        },
        // Update-channel enrollment writes to the env's local secrets backend
        // and talks to the external Cert-CA — not a remote-store operation.
        OpNoun::Updates { verb } => match verb {
            UpdatesVerb::Enroll(_) => Err(not_supported("updates enroll")),
            UpdatesVerb::Status { .. } => Err(not_supported("updates status")),
            UpdatesVerb::Get(_) => Err(not_supported("updates get")),
            UpdatesVerb::Apply(_) => Err(not_supported("updates apply")),
            UpdatesVerb::Recover(_) => Err(not_supported("updates recover")),
            UpdatesVerb::ConfigSet(_) => Err(not_supported("updates config-set")),
            UpdatesVerb::ConfigShow { .. } => Err(not_supported("updates config-show")),
            UpdatesVerb::PlanBuild(_) => Err(not_supported("updates plan-build")),
            // Signs with the local operator key against the local env trust
            // root; the remote store holds neither.
            UpdatesVerb::Publish(_) => Err(not_supported("updates publish")),
        },
    }
}

/// Build the `NotYetImplemented` error for a local-only verb.
fn not_supported(noun_verb: &str) -> OpError {
    OpError::NotYetImplemented(format!(
        "`{noun_verb}` is a read/local-only verb not supported against a \
         remote --store-url store; run it without --store-url / \
         GREENTIC_STORE_URL against the local store"
    ))
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn resolve_payload<T: serde::de::DeserializeOwned>(
    flags: &OpFlags,
    payload: Option<T>,
) -> Result<T, OpError> {
    if let Some(p) = payload {
        return Ok(p);
    }
    if let Some(path) = &flags.answers {
        return super::load_answers::<T>(path);
    }
    Err(OpError::InvalidArgument(
        "no payload provided: pass --answers <path> or supply the payload directly".to_string(),
    ))
}

fn parse_env_id(raw: &str) -> Result<EnvId, OpError> {
    EnvId::try_from(raw).map_err(|e| OpError::InvalidArgument(format!("environment_id: {e}")))
}

fn parse_deployment_id(raw: &str) -> Result<DeploymentId, OpError> {
    use std::str::FromStr;
    let ulid = ulid::Ulid::from_str(raw)
        .map_err(|e| OpError::InvalidArgument(format!("deployment_id: {e}")))?;
    Ok(DeploymentId(ulid))
}

fn parse_revision_id(raw: &str) -> Result<RevisionId, OpError> {
    use std::str::FromStr;
    let ulid = ulid::Ulid::from_str(raw)
        .map_err(|e| OpError::InvalidArgument(format!("revision_id: {e}")))?;
    Ok(RevisionId(ulid))
}

fn parse_endpoint_id(raw: &str) -> Result<MessagingEndpointId, OpError> {
    use std::str::FromStr;
    ulid::Ulid::from_str(raw)
        .map(MessagingEndpointId)
        .map_err(|e| OpError::InvalidArgument(format!("endpoint_id: {e}")))
}

fn parse_bundle_id(raw: &str) -> Result<BundleId, OpError> {
    if raw.trim().is_empty() {
        return Err(OpError::InvalidArgument(
            "bundle_id must not be empty".to_string(),
        ));
    }
    Ok(BundleId::new(raw))
}

fn require_nonempty(field: &str, value: &str) -> Result<String, OpError> {
    if value.trim().is_empty() {
        return Err(OpError::InvalidArgument(format!(
            "{field} must not be empty"
        )));
    }
    Ok(value.to_string())
}

// ---------------------------------------------------------------------------
// env: create, update, set-public-url
// ---------------------------------------------------------------------------

fn remote_env_create(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
    payload: Option<super::env::EnvCreatePayload>,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let parsed_listen_addr = payload
        .listen_addr
        .as_deref()
        .map(|raw| {
            raw.parse::<std::net::SocketAddr>().map_err(|e| {
                OpError::InvalidArgument(format!(
                    "listen_addr {raw:?} is not a valid socket address: {e}"
                ))
            })
        })
        .transpose()?;
    let parsed_public_base_url =
        super::env::parse_optional_public_base_url(&payload.public_base_url)?;
    let env = store
        .create_environment(
            &env_id,
            payload.name,
            EnvironmentHostConfig {
                env_id: env_id.clone(),
                region: payload.region,
                tenant_org_id: payload.tenant_org_id,
                listen_addr: parsed_listen_addr,
                public_base_url: parsed_public_base_url,
                gui_enabled: None,
            },
        )
        .map_err(map_store_err_preserving_noun)?;
    Ok(OpOutcome::new(
        "env",
        "create",
        serde_json::to_value(super::env::EnvSummary::from(&env)).expect("EnvSummary is json-safe"),
    ))
}

fn remote_env_update(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
    payload: Option<super::env::EnvCreatePayload>,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let parsed_public_base_url =
        super::env::parse_optional_public_base_url(&payload.public_base_url)?;
    let env = store
        .update_environment(
            &env_id,
            UpdateEnvironmentPayload {
                name: Some(payload.name),
                region: FieldUpdate::from_option(payload.region),
                tenant_org_id: FieldUpdate::from_option(payload.tenant_org_id),
                listen_addr: FieldUpdate::Keep,
                public_base_url: FieldUpdate::from_option(parsed_public_base_url),
                gui_enabled: FieldUpdate::Keep,
            },
        )
        .map_err(map_store_err_preserving_noun)?;
    Ok(OpOutcome::new(
        "env",
        "update",
        serde_json::to_value(super::env::EnvSummary::from(&env)).expect("EnvSummary is json-safe"),
    ))
}

fn remote_env_set_public_url(
    store: &dyn EnvironmentMutations,
    env_id_raw: &str,
    url: &str,
) -> Result<OpOutcome, OpError> {
    let env_id = parse_env_id(env_id_raw)?;
    let validated = super::env::parse_public_base_url(url)?;
    let env = store
        .update_environment(
            &env_id,
            UpdateEnvironmentPayload {
                public_base_url: FieldUpdate::Set(validated),
                ..Default::default()
            },
        )
        .map_err(map_store_err_preserving_noun)?;
    Ok(OpOutcome::new(
        "env",
        "set-public-url",
        json!({
            "environment_id": env_id.as_str(),
            "host_config": env.host_config,
        }),
    ))
}

// ---------------------------------------------------------------------------
// env-packs: add, update, remove, rollback
// ---------------------------------------------------------------------------

fn remote_env_packs_add(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload::<super::env_packs::EnvPackBindingPayload>(flags, None)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let binding = super::env_packs::build_binding(&payload, 0, None)?;
    let idempotency_key = super::resolve_idempotency_key(payload.idempotency_key)?;
    let added = store
        .add_pack_binding(&env_id, binding, idempotency_key)
        .map_err(map_store_err_preserving_noun)?;
    Ok(OpOutcome::new(
        "env-packs",
        "add",
        serde_json::to_value(super::env_packs::BindingSummary::from_binding(
            &env_id, &added,
        ))
        .expect("BindingSummary is json-safe"),
    ))
}

fn remote_env_packs_update(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload::<super::env_packs::EnvPackBindingPayload>(flags, None)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let slot = payload.slot;
    let binding = super::env_packs::build_binding(&payload, 0, None)?;
    let idempotency_key = super::resolve_idempotency_key(payload.idempotency_key)?;
    let (new_binding, _new_generation) = store
        .update_pack_binding(&env_id, slot, binding, idempotency_key)
        .map_err(map_store_err_preserving_noun)?;
    Ok(OpOutcome::new(
        "env-packs",
        "update",
        serde_json::to_value(super::env_packs::BindingSummary::from_binding(
            &env_id,
            &new_binding,
        ))
        .expect("BindingSummary is json-safe"),
    ))
}

fn remote_env_packs_remove(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload::<super::env_packs::EnvPackRemovePayload>(flags, None)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let slot = payload.slot;
    let idempotency_key = super::resolve_idempotency_key(payload.idempotency_key)?;
    let (removed, _removed_generation) = store
        .remove_pack_binding(&env_id, slot, idempotency_key)
        .map_err(map_store_err_preserving_noun)?;
    Ok(OpOutcome::new(
        "env-packs",
        "remove",
        serde_json::to_value(super::env_packs::BindingSummary::from_binding(
            &env_id, &removed,
        ))
        .expect("BindingSummary is json-safe"),
    ))
}

fn remote_env_packs_rollback(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload::<super::env_packs::EnvPackRemovePayload>(flags, None)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let slot = payload.slot;
    let idempotency_key = super::resolve_idempotency_key(payload.idempotency_key)?;
    let (restored, _new_generation) = store
        .rollback_pack_binding(&env_id, slot, idempotency_key)
        .map_err(map_store_err_preserving_noun)?;
    Ok(OpOutcome::new(
        "env-packs",
        "rollback",
        serde_json::to_value(super::env_packs::BindingSummary::from_binding(
            &env_id, &restored,
        ))
        .expect("BindingSummary is json-safe"),
    ))
}

// ---------------------------------------------------------------------------
// extensions: add, update, remove, rollback
// ---------------------------------------------------------------------------

fn remote_extensions_add(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload::<super::extensions::ExtensionBindingPayload>(flags, None)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let binding = super::extensions::build_binding(&payload, 0, None)?;
    let idempotency_key = super::resolve_idempotency_key(payload.idempotency_key)?;
    let added = store
        .add_extension_binding(&env_id, binding, idempotency_key)
        .map_err(map_store_err_preserving_noun)?;
    Ok(OpOutcome::new(
        "extensions",
        "add",
        serde_json::to_value(super::extensions::ExtensionSummary::from_binding(
            &env_id, &added,
        ))
        .expect("ExtensionSummary is json-safe"),
    ))
}

fn remote_extensions_update(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload::<super::extensions::ExtensionBindingPayload>(flags, None)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let key = super::extensions::build_key(&payload.kind, &payload.instance_id)?;
    let binding = super::extensions::build_binding(&payload, 0, None)?;
    let idempotency_key = super::resolve_idempotency_key(payload.idempotency_key)?;
    let (updated, _new_generation) = store
        .update_extension_binding(&env_id, key, binding, idempotency_key)
        .map_err(map_store_err_preserving_noun)?;
    Ok(OpOutcome::new(
        "extensions",
        "update",
        serde_json::to_value(super::extensions::ExtensionSummary::from_binding(
            &env_id, &updated,
        ))
        .expect("ExtensionSummary is json-safe"),
    ))
}

fn remote_extensions_remove(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload::<super::extensions::ExtensionRemovePayload>(flags, None)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let key = super::extensions::build_key(&payload.kind, &payload.instance_id)?;
    let idempotency_key = super::resolve_idempotency_key(payload.idempotency_key)?;
    let (removed, _generation) = store
        .remove_extension_binding(&env_id, key, idempotency_key)
        .map_err(map_store_err_preserving_noun)?;
    Ok(OpOutcome::new(
        "extensions",
        "remove",
        serde_json::to_value(super::extensions::ExtensionSummary::from_binding(
            &env_id, &removed,
        ))
        .expect("ExtensionSummary is json-safe"),
    ))
}

fn remote_extensions_rollback(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload::<super::extensions::ExtensionRemovePayload>(flags, None)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let key = super::extensions::build_key(&payload.kind, &payload.instance_id)?;
    let idempotency_key = super::resolve_idempotency_key(payload.idempotency_key)?;
    let (restored, _new_generation) = store
        .rollback_extension_binding(&env_id, key, idempotency_key)
        .map_err(map_store_err_preserving_noun)?;
    Ok(OpOutcome::new(
        "extensions",
        "rollback",
        serde_json::to_value(super::extensions::ExtensionSummary::from_binding(
            &env_id, &restored,
        ))
        .expect("ExtensionSummary is json-safe"),
    ))
}

// ---------------------------------------------------------------------------
// bundles: add, update, remove
// ---------------------------------------------------------------------------

fn remote_bundles_add(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload::<super::bundles::BundleAddPayload>(flags, None)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    if payload.bundle_id.trim().is_empty() {
        return Err(OpError::InvalidArgument(
            "bundle_id must not be empty".to_string(),
        ));
    }
    let bundle_id = BundleId::new(payload.bundle_id);
    let customer_id = super::bundles::resolve_customer_id(&env_id, payload.customer_id)?;
    let revenue_share = super::bundles::convert_revenue_share(&payload.revenue_share);
    let route_binding_payload = payload.route_binding.clone();
    let idempotency_key = super::resolve_idempotency_key(payload.idempotency_key)?;
    let deployment = store
        .add_bundle(
            &env_id,
            AddBundlePayload {
                bundle_id,
                customer_id,
                revenue_share,
                route_binding: Some(super::bundles::into_route_binding(route_binding_payload)),
                authorization_ref: Some(payload.authorization_ref.to_string_lossy().into_owned()),
                config_overrides: payload.config_overrides,
            },
            idempotency_key,
        )
        .map_err(map_store_err_preserving_noun)?;
    Ok(OpOutcome::new(
        "bundles",
        "add",
        serde_json::to_value(super::bundles::BundleSummary::from(&env_id, &deployment))
            .expect("BundleSummary is json-safe"),
    ))
}

fn remote_bundles_update(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload::<super::bundles::BundleUpdatePayload>(flags, None)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let deployment_id = parse_deployment_id(&payload.deployment_id)?;
    let new_revenue_share: Option<Vec<RevenueShareEntry>> = payload
        .revenue_share
        .as_ref()
        .map(|s| super::bundles::convert_revenue_share(s));
    let new_route_binding = payload
        .route_binding
        .clone()
        .map(super::bundles::into_route_binding);
    let idempotency_key = super::resolve_idempotency_key(payload.idempotency_key)?;
    let deployment = store
        .update_bundle(
            &env_id,
            UpdateBundlePayload {
                deployment_id,
                status: payload.status,
                route_binding: new_route_binding,
                revenue_share: new_revenue_share,
                config_overrides: payload.config_overrides,
            },
            idempotency_key,
        )
        .map_err(map_store_err_preserving_noun)?;
    Ok(OpOutcome::new(
        "bundles",
        "update",
        serde_json::to_value(super::bundles::BundleSummary::from(&env_id, &deployment))
            .expect("BundleSummary is json-safe"),
    ))
}

fn remote_bundles_remove(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload::<super::bundles::BundleRemovePayload>(flags, None)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let deployment_id = parse_deployment_id(&payload.deployment_id)?;
    let idempotency_key = super::resolve_idempotency_key(payload.idempotency_key)?;
    let RemoveBundleOutcome {
        deployment,
        pruned_revision_ids,
    } = store
        .remove_bundle(&env_id, deployment_id, idempotency_key)
        .map_err(map_store_err_preserving_noun)?;
    let mut result =
        serde_json::to_value(super::bundles::BundleSummary::from(&env_id, &deployment))
            .expect("BundleSummary is json-safe");
    result["pruned_revision_ids"] = json!(
        pruned_revision_ids
            .iter()
            .map(|r| r.to_string())
            .collect::<Vec<_>>()
    );
    Ok(OpOutcome::new("bundles", "remove", result))
}

// ---------------------------------------------------------------------------
// traffic: set, rollback
// ---------------------------------------------------------------------------

fn remote_traffic_set(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
    payload: Option<super::traffic::TrafficSetPayload>,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let deployment_id = parse_deployment_id(&payload.deployment_id)?;
    let parsed_entries = super::traffic::parse_entries(&payload.entries)?;
    // Skip the local store.load "revision-belongs-to-deployment" pre-check —
    // the typed verb `set_traffic_split` enforces it server-side.
    let idempotency_key = IdempotencyKey::new(payload.idempotency_key)
        .map_err(|e| OpError::InvalidArgument(format!("idempotency_key: {e}")))?;
    let outcome = store
        .set_traffic_split(
            &env_id,
            greentic_deploy_spec::SetTrafficSplitPayload {
                deployment_id,
                entries: parsed_entries,
                updated_by: payload.updated_by,
                authorization_ref: Some(payload.authorization_ref.to_string_lossy().into_owned()),
            },
            idempotency_key,
        )
        .map_err(super::traffic::map_traffic_store_err)?;
    // Telemetry parity with the local dispatch: the outcome carries the
    // post-mutation env snapshot, so no local read is needed over HTTP.
    super::traffic::emit_applied_telemetry(&outcome);
    Ok(OpOutcome::new(
        "traffic",
        "set",
        serde_json::to_value(super::traffic::TrafficSummary::from(
            &env_id,
            &outcome.split,
        ))
        .expect("TrafficSummary is json-safe"),
    ))
}

fn remote_traffic_rollback(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
    payload: Option<super::traffic::TrafficShowPayload>,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let deployment_id = parse_deployment_id(&payload.deployment_id)?;
    let idempotency_key = super::resolve_idempotency_key(payload.idempotency_key)?;
    let outcome = store
        .rollback_traffic_split(&env_id, deployment_id, idempotency_key)
        .map_err(super::traffic::map_traffic_store_err)?;
    super::traffic::emit_rollback_telemetry(&outcome);
    Ok(OpOutcome::new(
        "traffic",
        "rollback",
        serde_json::to_value(super::traffic::TrafficSummary::from(
            &env_id,
            &outcome.restored,
        ))
        .expect("TrafficSummary is json-safe"),
    ))
}

// ---------------------------------------------------------------------------
// revisions: drain, archive
// ---------------------------------------------------------------------------

/// Shared remote driver for the revision lifecycle transitions
/// (`drain` / `archive`). Both resolve the same payload, call their typed
/// verb, emit the matching rollout event from the returned outcome, and
/// render a `RevisionSummary` — they differ only by verb label and store
/// method. `emit_for_op` keys on the starting lifecycle, so `archive` emits
/// `RevisionEvicted` only for the post-drain (`Inactive → Archived`)
/// eviction hop. Telemetry parity with the local helper: the typed verb's
/// outcome carries the post-mutation env + revision, so no local read is
/// needed over HTTP.
fn remote_revision_transition(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
    verb: &'static str,
    transition: impl Fn(
        &dyn EnvironmentMutations,
        &EnvId,
        RevisionId,
        IdempotencyKey,
    ) -> Result<
        crate::environment::RevisionTransitionOutcome,
        crate::environment::StoreError,
    >,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload::<super::revisions::RevisionTransitionPayload>(flags, None)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let revision_id = parse_revision_id(&payload.revision_id)?;
    let idempotency_key = super::resolve_idempotency_key(payload.idempotency_key)?;
    let outcome = transition(store, &env_id, revision_id, idempotency_key)
        .map_err(map_store_err_preserving_noun)?;
    super::revisions::emit_for_op(
        verb,
        false,
        Some(outcome.starting_lifecycle),
        &outcome.environment,
        &outcome.revision,
    );
    Ok(OpOutcome::new(
        "revisions",
        verb,
        serde_json::to_value(super::revisions::RevisionSummary::from(&outcome.revision))
            .expect("RevisionSummary is json-safe"),
    ))
}

// ---------------------------------------------------------------------------
// revisions: stage, warm
// ---------------------------------------------------------------------------

/// Remote `revisions stage`. The store only persists the revision's pinned
/// artifact pointers — the server's `stage_revision` runs a pure in-memory
/// transform and never touches bundle bytes — so a remote stage works from
/// caller-supplied pointers alone. The direct `--bundle <local.gtbundle>` CLI
/// path extracts a LOCAL artifact and cannot run against a remote store, so it
/// is rejected with a push-to-registry hint; the pin-pointer path (reachable
/// via `--answers <file>`) maps onto [`StageRevisionPayload`].
///
/// Because a remote worker has no local disk to fall back to, the pin-pointer
/// answers MUST carry a real `bundle_source_uri` + non-placeholder
/// `bundle_digest` (else `warm` could promote a revision no worker can
/// materialize). Supply a stable `revision_id` + `idempotency_key` to make a
/// lost-response retry replay the original outcome instead of double-staging.
fn remote_revision_stage(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
    args: super::dispatch::RevisionStageArgs,
) -> Result<OpOutcome, OpError> {
    // `payload_from_stage_args` returns `Some` only when positional args were
    // given, and it always requires `--bundle` — so a `Some` here is the
    // local-artifact path, which has no meaning against a remote store.
    if super::revisions::payload_from_stage_args(args)?.is_some() {
        return Err(OpError::InvalidArgument(
            "`revisions stage <env> --bundle <local.gtbundle>` cannot run against a remote \
             --store-url store: the local artifact can't be extracted server-side. Push the \
             bundle to a registry, then stage with `--answers <file>` carrying pinned pointers \
             (bundle_digest, bundle_source_uri, pack_list, pack_list_lock_ref)."
                .to_string(),
        ));
    }
    let payload = resolve_payload::<super::revisions::RevisionStagePayload>(flags, None)?;
    if payload.bundle_path.is_some() {
        return Err(OpError::InvalidArgument(
            "remote `revisions stage` needs pinned pointers, not a local `bundle_path`: push the \
             bundle to a registry and supply bundle_source_uri + bundle_digest + pack_list."
                .to_string(),
        ));
    }
    let env_id = parse_env_id(&payload.environment_id)?;
    let deployment_id = parse_deployment_id(&payload.deployment_id)?;

    // A remote store keeps no local artifact bytes — a revision is only
    // servable if a remote worker can pull and verify its bundle. The local
    // pin-pointer defaults (`bundle_source_uri: None`, `bundle_digest:
    // "sha256:00"`) are local-serve placeholders that would strand a remote
    // worker (and `warm` would then promote an unservable revision), so require
    // real pointers here.
    let bundle_source_uri = payload
        .bundle_source_uri
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            OpError::InvalidArgument(
                "remote `revisions stage` requires `bundle_source_uri` (oci://… / repo://… / \
                 store://…) so a remote worker can pull the bundle at boot"
                    .to_string(),
            )
        })?;
    if payload.bundle_digest.trim().is_empty()
        || payload.bundle_digest == super::revisions::default_bundle_digest()
    {
        return Err(OpError::InvalidArgument(
            "remote `revisions stage` requires a real `bundle_digest` — the placeholder default \
             cannot be verified by a remote worker"
                .to_string(),
        ));
    }

    // Honor a caller-pinned revision id + idempotency key so a lost-response
    // retry replays the original outcome (A8 §2) instead of staging a second
    // revision under the same deployment. BOTH must be stable: the server
    // fingerprints the request body (which carries the revision id), so a fresh
    // id would change the fingerprint and defeat replay even with a stable key.
    // Absent either, mint — a one-shot remote stage is still correct, just not
    // retry-safe.
    let revision_id = match payload.revision_id.as_deref() {
        Some(raw) => parse_revision_id(raw)?,
        None => crate::environment::mint_revision_id(),
    };
    let idempotency_key = super::resolve_idempotency_key(payload.idempotency_key)?;

    let pack_list = super::revisions::parse_pack_list(payload.pack_list)?;
    let store_payload = StageRevisionPayload {
        revision_id,
        deployment_id,
        bundle_digest: payload.bundle_digest,
        bundle_source_uri: Some(bundle_source_uri),
        pack_list,
        pack_list_lock_ref: payload.pack_list_lock_ref,
        // Pack-config docs are materialized only on the local `--bundle` path;
        // a remote pin-pointer stage references none.
        pack_config_refs: Vec::new(),
        config_digest: payload.config_digest,
        signature_sidecar_ref: payload.signature_sidecar_ref,
        drain_seconds: payload.drain_seconds,
    };
    let revision = store
        .stage_revision(&env_id, store_payload, idempotency_key)
        .map_err(map_store_err_preserving_noun)?;
    Ok(OpOutcome::new(
        "revisions",
        "stage",
        serde_json::to_value(super::revisions::RevisionSummary::from(&revision))
            .expect("RevisionSummary is json-safe"),
    ))
}

/// Remote `revisions warm`. Reads the env to capture the current revision
/// lifecycle (the `expected_lifecycle` precondition the server re-checks), then
/// ships the typed warm with a Noop health gate — matching the CLI default
/// [`super::revisions::warm`], which warms behind an always-`Ok` gate.
/// Producers that run a real warm/ready gate stay local-only for now.
fn remote_revision_warm(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload::<super::revisions::RevisionTransitionPayload>(flags, None)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let revision_id = parse_revision_id(&payload.revision_id)?;
    let idempotency_key = super::resolve_idempotency_key(payload.idempotency_key)?;
    // Read the current lifecycle for the warm precondition (the local path
    // reads it inline under its flock). The server re-checks it before applying
    // the gate result, so a racing transition is rejected, not silently warmed.
    let env = store
        .load_environment(&env_id)
        .map_err(map_store_err_preserving_noun)?;
    let current_lifecycle = env
        .revisions
        .iter()
        .find(|r| r.revision_id == revision_id)
        .map(|r| r.lifecycle)
        .ok_or_else(|| {
            OpError::NotFound(format!(
                "revision `{revision_id}` not found in env `{env_id}`"
            ))
        })?;
    let outcome = store
        .warm_revision(
            &env_id,
            WarmRevisionPayload {
                revision_id,
                health_gate: Ok(()),
                expected_lifecycle: current_lifecycle,
            },
            idempotency_key,
        )
        .map_err(map_store_err_preserving_noun)?;
    super::revisions::emit_for_op(
        "warm",
        false,
        Some(outcome.starting_lifecycle),
        &outcome.environment,
        &outcome.revision,
    );
    Ok(OpOutcome::new(
        "revisions",
        "warm",
        serde_json::to_value(super::revisions::RevisionSummary::from(&outcome.revision))
            .expect("RevisionSummary is json-safe"),
    ))
}

// ---------------------------------------------------------------------------
// deploy (composite: add → stage → warm → traffic over the remote store)
// ---------------------------------------------------------------------------

/// Deterministic staged-revision id for a retry-safe remote deploy: the same
/// deploy `idempotency_key` always derives the same id, so a lost-response retry
/// stages (and the server replays) the SAME revision instead of minting a
/// duplicate Staged/Ready one. A one-shot deploy (no key) mints a fresh id.
fn deploy_revision_id(idempotency_key: Option<&str>) -> RevisionId {
    match idempotency_key {
        Some(key) => {
            let digest = Sha256::digest(format!("greentic-deploy-revision:{key}").as_bytes());
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&digest[..16]);
            RevisionId(ulid::Ulid::from_bytes(bytes))
        }
        None => crate::environment::mint_revision_id(),
    }
}

/// Remote `op deploy` over `--store-url`. Runs the same blue-green rollout as
/// the local [`deploy`](super::deploy::deploy) — add the bundle deployment (when
/// new), stage a revision, warm it, route 100 % of traffic — but against the
/// HTTP store and from caller-pinned artifact pointers. A control-plane store
/// keeps no bundle bytes, so the local `--bundle <local.gtbundle>` path is
/// rejected with a push-to-registry hint: the caller supplies a
/// `bundle_source_uri` and a real `bundle_digest` (plus optional `pack_list` /
/// lock) via `--answers`, exactly like remote `revisions stage`. The rollout
/// decisions (idempotent replay, deployment reuse, route immutability,
/// superseded revisions) are the shared `super::deploy` helpers; the execution
/// sequence (add → stage → warm → traffic) mirrors local `deploy()`, so keep the
/// two in sync until a shared rollout engine lands. The cut-over reuses
/// `remote_traffic_set` so entry parsing and telemetry stay single-sourced.
fn remote_deploy(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
    payload: Option<super::deploy::BundleDeployPayload>,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload::<super::deploy::BundleDeployPayload>(flags, payload)?;

    // A remote store can't extract a local artifact server-side.
    if payload.bundle_path.is_some() {
        return Err(OpError::InvalidArgument(
            "`op deploy --bundle <local.gtbundle>` cannot run against a remote --store-url \
             store: the local artifact can't be extracted server-side. Push the bundle to a \
             registry, then deploy with `--answers <file>` carrying pinned pointers \
             (bundle_source_uri, bundle_digest, pack_list)."
                .to_string(),
        ));
    }

    let env_id = parse_env_id(&payload.environment_id)?;
    let bundle_id = payload.bundle_id.trim().to_string();
    if bundle_id.is_empty() {
        return Err(OpError::InvalidArgument(
            "bundle_id must not be empty".to_string(),
        ));
    }
    if let Some(rb) = payload.route_binding.as_ref() {
        rb.validate()?;
    }
    let customer_id = super::bundles::resolve_customer_id(&env_id, payload.customer_id.clone())?;

    // Require real pins: a placeholder digest or missing source URI would strand
    // a remote worker (and `warm` would then promote an unservable revision).
    // Mirrors remote `revisions stage`.
    let pins = payload.remote_pins.clone().unwrap_or_default();
    let bundle_source_uri = payload
        .bundle_source_uri
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            OpError::InvalidArgument(
                "remote `op deploy` requires `bundle_source_uri` (oci://… / repo://… / \
                 store://…) so a remote worker can pull the bundle at boot"
                    .to_string(),
            )
        })?;
    // Reuse the shared `remote_pullable_digest` (→ `digest_is_real`) so the
    // `sha256:…`-shaped, non-placeholder rule has ONE definition across the
    // remote stage / apply / deploy paths (the inline check used to be looser —
    // it would have accepted a malformed, non-`sha256:` digest).
    let bundle_digest = pins.bundle_digest.as_deref().map(str::trim);
    if !remote_pullable_digest(bundle_digest) {
        return Err(OpError::InvalidArgument(
            "remote `op deploy` requires a real pinned `bundle_digest` (sha256:…) in remote_pins \
             — a remote worker cannot verify a placeholder or unpinned pull"
                .to_string(),
        ));
    }
    let bundle_digest = bundle_digest
        .expect("remote_pullable_digest is false for None")
        .to_string();

    // Validate ALL caller pins — including the pack list, which can fail on a
    // malformed version string — BEFORE any store mutation, so a bad answers
    // file can never commit a bundle it then can't roll out (Codex finding 1).
    let pack_list = super::revisions::parse_pack_list(pins.pack_list.clone())?;

    // Retry-safety (A8 §2): when the caller pins a deploy `idempotency_key`, the
    // staged revision id AND every sub-operation key are DERIVED from it, so a
    // lost-response retry replays the same add/stage/warm/traffic instead of
    // minting a duplicate revision (orphaning the prior Staged/Ready one). A
    // one-shot deploy (no key) mints, exactly like the local path. Distinct
    // suffixes keep the sub-op keys from colliding (same key + different body is
    // a 409 idempotency-conflict); the cut-over keeps the BARE key so a completed
    // retry is short-circuited by `idempotent_deploy_replay` above.
    let deploy_key = payload.idempotency_key.clone();
    let staged_revision_id = deploy_revision_id(deploy_key.as_deref());
    let sub_key = |suffix: &str| -> Result<IdempotencyKey, OpError> {
        super::resolve_idempotency_key(deploy_key.as_deref().map(|k| format!("{k}:{suffix}")))
    };

    // Load the env once for the rollout decisions (shared with the local path).
    let env = store
        .load_environment(&env_id)
        .map_err(map_store_err_preserving_noun)?;
    let existing = super::deploy::find_existing_deployment(&env, &bundle_id, &customer_id);

    // Idempotent replay: a keyed deploy whose split already exists echoes the
    // prior outcome without minting a duplicate revision or moving the rollback
    // target.
    if let Some((deployment_id, revision_id)) =
        super::deploy::idempotent_deploy_replay(&env, existing, payload.idempotency_key.as_deref())
    {
        return Ok(super::deploy::DeploySummary::routed_outcome(
            &env_id,
            bundle_id,
            deployment_id,
            revision_id,
            true,
            Vec::new(),
        ));
    }
    super::deploy::ensure_route_binding_unchanged(existing, payload.route_binding.as_ref())?;

    // Resolve the deployment: reuse the existing one (blue-green) or add fresh.
    let (deployment_id, reused, superseded) = match existing {
        Some(b) => {
            let dep = b.deployment_id;
            (dep, true, super::deploy::superseded_revisions(&env, dep))
        }
        None => {
            let deployment = store
                .add_bundle(
                    &env_id,
                    AddBundlePayload {
                        bundle_id: BundleId::new(bundle_id.clone()),
                        customer_id: customer_id.clone(),
                        revenue_share: super::bundles::convert_revenue_share(
                            &payload
                                .revenue_share
                                .clone()
                                .unwrap_or_else(super::bundles::default_revenue_share),
                        ),
                        route_binding: Some(super::bundles::into_route_binding(
                            payload.route_binding.clone().unwrap_or_default(),
                        )),
                        authorization_ref: Some(
                            super::bundles::default_authorization_ref()
                                .to_string_lossy()
                                .into_owned(),
                        ),
                        config_overrides: payload.config_overrides.clone().unwrap_or_default(),
                    },
                    sub_key("add")?,
                )
                .map_err(map_store_err_preserving_noun)?;
            (deployment.deployment_id, false, Vec::new())
        }
    };
    drop(env);

    // Stage the pinned revision (the pack list was validated up-front).
    let revision = store
        .stage_revision(
            &env_id,
            StageRevisionPayload {
                revision_id: staged_revision_id,
                deployment_id,
                bundle_digest,
                bundle_source_uri: Some(bundle_source_uri),
                pack_list,
                pack_list_lock_ref: pins.pack_list_lock_ref.clone().unwrap_or_default(),
                pack_config_refs: Vec::new(),
                config_digest: pins
                    .config_digest
                    .clone()
                    .unwrap_or_else(super::revisions::default_config_digest),
                signature_sidecar_ref: pins
                    .signature_sidecar_ref
                    .clone()
                    .unwrap_or_else(super::revisions::default_signature_sidecar_ref),
                drain_seconds: pins
                    .drain_seconds
                    .unwrap_or_else(super::revisions::default_drain_seconds),
            },
            sub_key("stage")?,
        )
        .map_err(map_store_err_preserving_noun)?;
    let revision_id = revision.revision_id;

    // Warm it to Ready behind the no-op gate (deploy has no health producers).
    store
        .warm_revision(
            &env_id,
            WarmRevisionPayload {
                revision_id,
                health_gate: Ok(()),
                expected_lifecycle: revision.lifecycle,
            },
            sub_key("warm")?,
        )
        .map_err(map_store_err_preserving_noun)?;

    // Re-deploy override replacement: after warm, before cut-over (so a failed
    // stage/warm never replaces the live deployment's overrides).
    if reused && let Some(ref overrides) = payload.config_overrides {
        store
            .update_bundle(
                &env_id,
                UpdateBundlePayload {
                    deployment_id,
                    status: None,
                    route_binding: None,
                    revenue_share: None,
                    config_overrides: Some(overrides.clone()),
                },
                sub_key("override")?,
            )
            .map_err(map_store_err_preserving_noun)?;
    }

    // Route 100 % to the new revision. Reuse the remote traffic verb so entry
    // parsing + telemetry stay single-sourced.
    let cutover_key = payload
        .idempotency_key
        .clone()
        .unwrap_or_else(|| format!("deploy:{deployment_id}:{revision_id}"));
    remote_traffic_set(
        store,
        flags,
        Some(super::traffic::TrafficSetPayload {
            environment_id: env_id.as_str().to_string(),
            deployment_id: deployment_id.to_string(),
            entries: vec![super::traffic::TrafficSetEntryPayload {
                revision_id: revision_id.to_string(),
                weight_bps: Some(super::deploy::FULL_TRAFFIC_BPS),
                weight_percent: None,
            }],
            updated_by: super::traffic::default_updated_by(),
            idempotency_key: cutover_key,
            authorization_ref: super::traffic::default_authorization_ref(),
        }),
    )?;

    Ok(super::deploy::DeploySummary::routed_outcome(
        &env_id,
        bundle_id,
        deployment_id.to_string(),
        revision_id.to_string(),
        reused,
        superseded,
    ))
}

/// The `--answers` payload for remote `env reconcile`. The control-plane store
/// holds NO answer blobs (the remote apply path strips every binding
/// `answers_ref`), so the operator supplies the reconcile-time execution context
/// locally — the same two answer objects the local path reads from the env's
/// Deployer- and Secrets-slot `answers_ref` files. `deny_unknown_fields` so a
/// mistyped top-level key fails closed instead of silently defaulting (an empty
/// `deployer_answers` would target the ambient cluster context).
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteReconcilePayload {
    /// Deployer-slot (k8s) answers: `kubeconfig_context`, `namespace`,
    /// `runtime_image`, router overrides — the same shape the Deployer binding's
    /// `answers_ref` file holds locally. Absent → ambient kubeconfig context.
    #[serde(default)]
    deployer_answers: Value,
    /// Secrets-slot Vault connection answers: `addr` + `role` required, mounts /
    /// prefix / transit / namespace default to the provider's — the same shape
    /// the Secrets binding's `answers_ref` file holds locally. Required: remote
    /// reconcile is Vault-only.
    #[serde(default)]
    secrets_answers: Value,
}

/// Remote `op env reconcile` over `--store-url`. Reads the desired-state
/// [`Environment`] to fail-fast on the structural gates, then runs the
/// server-mediated `env.reconcile` op (`reconcile_environment`) — the store
/// AUTHORIZEs + AUDITs + CAS-pins the reconcile and returns the authorized
/// snapshot — before running the SAME k8s convergence as local
/// [`reconcile`](super::env::reconcile) against it. Only the answer source and
/// the store-side authorization step differ from local. The store keeps no
/// answer blobs, so the operator supplies the reconcile-time context via
/// `--answers` ([`RemoteReconcilePayload`]); it is therefore Vault-secrets-only
/// (no local dev-store to ship values from), k8s-only (same gate as local), and
/// ships no dev-store Secret (`dev_secrets = None` — the worker resolves
/// `secret://` under pod identity). Keep the gate/sequence in sync with local
/// `reconcile` until a shared engine lands.
fn remote_reconcile(
    store: &HttpEnvironmentStore,
    flags: &OpFlags,
    args: super::dispatch::EnvReconcileArgs,
) -> Result<OpOutcome, OpError> {
    use greentic_deploy_spec::CapabilitySlot;

    let env_id = parse_env_id(&args.env_id)?;
    let env = store.load_environment(&env_id).map_err(|e| match e {
        StoreError::NotFound(_) => OpError::NotFound(format!(
            "environment `{env_id}` not found on the remote store"
        )),
        other => map_store_err_preserving_noun(other),
    })?;

    // k8s-only, same gate as local reconcile: resolve the live deployer kind
    // (honours `--kind`, refuses to switch deployers) then require it be k8s.
    let descriptor = super::env::resolve_live_deployer_kind(&env, args.kind.as_deref())?;
    let k8s_path = crate::env_packs::k8s::K8sDeployerHandler::DESCRIPTOR_PATH;
    if descriptor.path() != k8s_path {
        return Err(OpError::Conflict(format!(
            "remote env reconcile is only supported for the `{k8s_path}` deployer env-pack \
             today; `{}` cannot be reconciled to a live cluster",
            descriptor.path()
        )));
    }
    // Parity with local: confirm the kind is actually registered.
    crate::env_packs::EnvPackRegistry::with_builtins()
        .resolve_for_slot(CapabilitySlot::Deployer, &descriptor)
        .map_err(|e| OpError::Conflict(e.to_string()))?;

    // Vault-secrets-only: a remote store has no local dev-store to ship secret
    // values from, so an env whose Secrets backend is the dev-store (or has no
    // secrets binding at all) cannot be reconciled remotely. Fail closed on any
    // non-Vault kind and point at the local path.
    match env.pack_for_slot(CapabilitySlot::Secrets) {
        Some(b) if b.kind.path() == crate::defaults::VAULT_SECRETS_PATH => {}
        Some(b) if b.kind.path() == crate::defaults::DEV_STORE_SECRETS_PATH => {
            return Err(OpError::Conflict(
                "remote env reconcile requires a Vault secrets backend; this env binds the \
                 dev-store backend, whose secret values live on a local disk a remote store has \
                 none of — reconcile it locally (without `--store-url`)"
                    .to_string(),
            ));
        }
        Some(b) => {
            return Err(OpError::Conflict(format!(
                "unknown secrets backend kind `{}`; remote reconcile supports only `{}`",
                b.kind.path(),
                crate::defaults::VAULT_SECRETS_PATH
            )));
        }
        None => {
            return Err(OpError::Conflict(
                "remote env reconcile requires a Vault secrets binding; this env has none (the \
                 dev-store default ships values from a local disk a remote store has none of) — \
                 bind the Vault secrets pack first"
                    .to_string(),
            ));
        }
    }

    // The store holds no answer blobs — the operator supplies the reconcile-time
    // context locally.
    let Some(answers_path) = flags.answers.as_ref() else {
        return Err(OpError::InvalidArgument(
            "remote env reconcile requires `--answers <file>` carrying `deployer_answers` \
             (k8s: kubeconfig_context, …) and `secrets_answers` (Vault: addr, role, …) — the \
             control-plane store keeps no answer files"
                .to_string(),
        ));
    };
    let payload: RemoteReconcilePayload = super::load_answers(answers_path)?;

    // Map the supplied Vault answers to the runtime backend (fail-closed on a
    // missing `addr`/`role`) — the same pure mapping the local path uses. A null
    // block maps to `None` so the mapper's own "requires a non-empty addr" error
    // surfaces instead of a "must be a JSON object" one.
    let secrets_answers = (!payload.secrets_answers.is_null()).then_some(&payload.secrets_answers);
    let secrets_backend = super::env::secrets_backend_from_vault_answers(secrets_answers)?;

    // Deployer answers (kubeconfig_context, namespace, …); absent → ambient
    // kubeconfig context. Borrowed (like `secrets_answers` above) — `payload`
    // outlives both uses, so no clone of the answer tree.
    let deployer_answers =
        (!payload.deployer_answers.is_null()).then_some(&payload.deployer_answers);

    // Bound deployer identity — resolved BEFORE the authorization so a missing
    // identity fails fast (the same posture as the structural gates) and the
    // ONLY step left after the store records the authorization is the
    // unavoidable live cluster apply. A remote env has no local dev-store, so
    // resolve against an empty scratch store — the dev-store source is then a
    // guaranteed miss and resolution falls to the env var → in-cluster identity
    // Secret (the documented fresh-operator-machine path). No `credentials_ref`
    // → ambient.
    let scratch_dir = tempfile::tempdir().map_err(|e| {
        OpError::Conflict(format!(
            "creating a scratch dir for identity resolution: {e}"
        ))
    })?;
    let scratch = crate::environment::LocalFsStore::new(scratch_dir.path());
    let bound_token = crate::env_packs::k8s::bound_identity::resolve_bound_identity(
        &scratch,
        &env,
        &env_id,
        deployer_answers,
    )?;
    let identity = if bound_token.is_some() {
        "bound"
    } else {
        "ambient"
    };

    // Server-mediated authorization: the bare read above + the identity
    // resolution just now let us fail-fast on everything that does NOT touch the
    // cluster; now ask the control-plane store to AUTHORIZE + AUDIT + CAS-pin the
    // reconcile. `load_environment` cached the ETag we reviewed, which
    // `reconcile_environment` replays as the mandatory `If-Match`, so a revision
    // that advanced under us is refused (412) instead of silently reconciled.
    // The store returns the authorized snapshot — apply exactly that (CAS
    // guarantees it equals the gated `env`; rebind so the apply runs against the
    // revision the store authorized).
    //
    // This records an AUTHORIZATION (RBAC + CAS), NOT a completion: the store has
    // no cluster access, so the live apply below is reflected only in the
    // returned report (and the operator's CLI output), not yet reported back to
    // the store audit. A completion/failure report-back is a tracked follow-up.
    let idempotency_key = super::mint_idempotency_key();
    let env = store
        .reconcile_environment(&env_id, &idempotency_key)
        .map_err(|e| match e {
            StoreError::NotFound(_) => OpError::NotFound(format!(
                "environment `{env_id}` not found on the remote store"
            )),
            // The reconcile op's only conflict-class outcome is a CAS
            // precondition failure (412): the env advanced between the read and
            // the authorize. Append the actionable next step to the server's
            // ETag-bearing message.
            StoreError::Conflict(msg) => OpError::Conflict(format!(
                "{msg}; the environment may have advanced on the store since it was \
                 read — re-run `op env reconcile` to reconcile the current revision"
            )),
            other => map_store_err_preserving_noun(other),
        })?;

    // Run the SAME store-free convergence as local reconcile. No dev-store Secret
    // (`None`): the worker resolves `secret://` from Vault under pod identity.
    let report = super::env::reconcile_k8s_cluster(
        &env,
        deployer_answers,
        bound_token,
        None,
        secrets_backend,
        false,
    )?;

    Ok(OpOutcome::new(
        "env",
        "reconcile",
        json!({
            "environment_id": env.environment_id.as_str(),
            "kind": descriptor.as_str(),
            // Remote reconcile sources its answers from `--answers`, not a stored
            // `answers_ref` (the control-plane store keeps none).
            "answers_source": "--answers",
            "identity": identity,
            "applied_count": report.applied.len(),
            "pruned_count": report.pruned.len(),
            "applied": report.applied,
            "pruned": report.pruned,
        }),
    ))
}

// ---------------------------------------------------------------------------
// messaging: add, link-bundle, unlink-bundle, set-welcome-flow, remove
// ---------------------------------------------------------------------------

fn remote_messaging_add(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
    payload: Option<super::messaging::EndpointAddPayload>,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let provider_id = require_nonempty("provider_id", &payload.provider_id)?;
    let provider_type = require_nonempty("provider_type", &payload.provider_type)?;
    let display_name = require_nonempty("display_name", &payload.display_name)?;
    let updated_by = require_nonempty("updated_by", &payload.updated_by)?;
    // A control-plane store never mints webhook secrets, so a telegram-class
    // endpoint must arrive with a caller-supplied ref (the operator provisions
    // the value in its own secrets plane). Catch the omission locally with a
    // clear directive instead of a 501 round-trip. Reuse the engine's canonical
    // matcher so the rule cannot drift from the server's.
    if greentic_deploy_spec::engine::messaging::is_telegram_class(&provider_type)
        && payload.webhook_secret_ref.is_none()
    {
        return Err(OpError::InvalidArgument(
            "telegram-class endpoints over a remote --store-url store require \
             --webhook-secret-ref: the remote store does not mint webhook secrets, so \
             provision the value in your own secrets plane and pass its secret:// ref"
                .to_string(),
        ));
    }
    let idempotency_key = super::resolve_idempotency_key(payload.idempotency_key)?;
    let ep = store
        .add_messaging_endpoint(
            &env_id,
            AddMessagingEndpointPayload {
                provider_id,
                provider_type,
                display_name,
                secret_refs: payload.secret_refs,
                webhook_secret_ref: payload.webhook_secret_ref,
                updated_by,
            },
            idempotency_key,
        )
        .map_err(map_store_err_preserving_noun)?;
    Ok(OpOutcome::new(
        "messaging.endpoint",
        "add",
        serde_json::to_value(super::messaging::EndpointSummary::from(&env_id, &ep))
            .expect("EndpointSummary is json-safe"),
    ))
}

fn remote_messaging_link_bundle(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
    payload: Option<super::messaging::EndpointLinkBundlePayload>,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let endpoint_id = parse_endpoint_id(&payload.endpoint_id)?;
    let bundle_id = parse_bundle_id(&payload.bundle_id)?;
    let updated_by = require_nonempty("updated_by", &payload.updated_by)?;
    let idempotency_key = super::resolve_idempotency_key(payload.idempotency_key)?;
    let ep = store
        .link_messaging_bundle(&env_id, endpoint_id, bundle_id, updated_by, idempotency_key)
        .map_err(map_store_err_preserving_noun)?;
    Ok(OpOutcome::new(
        "messaging.endpoint",
        "link-bundle",
        serde_json::to_value(super::messaging::EndpointSummary::from(&env_id, &ep))
            .expect("EndpointSummary is json-safe"),
    ))
}

fn remote_messaging_unlink_bundle(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
    payload: Option<super::messaging::EndpointLinkBundlePayload>,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let endpoint_id = parse_endpoint_id(&payload.endpoint_id)?;
    let bundle_id = parse_bundle_id(&payload.bundle_id)?;
    let updated_by = require_nonempty("updated_by", &payload.updated_by)?;
    let idempotency_key = super::resolve_idempotency_key(payload.idempotency_key)?;
    let ep = store
        .unlink_messaging_bundle(&env_id, endpoint_id, bundle_id, updated_by, idempotency_key)
        .map_err(map_store_err_preserving_noun)?;
    Ok(OpOutcome::new(
        "messaging.endpoint",
        "unlink-bundle",
        serde_json::to_value(super::messaging::EndpointSummary::from(&env_id, &ep))
            .expect("EndpointSummary is json-safe"),
    ))
}

fn remote_messaging_set_welcome_flow(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
    payload: Option<super::messaging::EndpointSetWelcomeFlowPayload>,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let endpoint_id = parse_endpoint_id(&payload.endpoint_id)?;
    let bundle_id = parse_bundle_id(&payload.bundle_id)?;
    let pack_id = require_nonempty("pack_id", &payload.pack_id)?;
    let flow_id = require_nonempty("flow_id", &payload.flow_id)?;
    let updated_by = require_nonempty("updated_by", &payload.updated_by)?;
    let idempotency_key = super::resolve_idempotency_key(payload.idempotency_key)?;
    let ep = store
        .set_messaging_welcome_flow(
            &env_id,
            SetMessagingWelcomeFlowPayload {
                endpoint_id,
                bundle_id,
                pack_id: PackId::new(pack_id),
                flow_id,
                updated_by,
            },
            idempotency_key,
        )
        .map_err(map_store_err_preserving_noun)?;
    Ok(OpOutcome::new(
        "messaging.endpoint",
        "set-welcome-flow",
        serde_json::to_value(super::messaging::EndpointSummary::from(&env_id, &ep))
            .expect("EndpointSummary is json-safe"),
    ))
}

fn remote_messaging_remove(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
    payload: Option<super::messaging::EndpointRemovePayload>,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let endpoint_id = parse_endpoint_id(&payload.endpoint_id)?;
    require_nonempty("updated_by", &payload.updated_by)?;
    let removed_id = store
        .remove_messaging_endpoint(&env_id, endpoint_id)
        .map_err(map_store_err_preserving_noun)?;
    Ok(OpOutcome::new(
        "messaging.endpoint",
        "remove",
        json!({"environment_id": env_id.as_str(), "endpoint_id": removed_id.to_string()}),
    ))
}

fn remote_messaging_rotate(
    store: &HttpEnvironmentStore,
    flags: &OpFlags,
    payload: Option<super::messaging::EndpointRotateWebhookSecretPayload>,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let endpoint_id = parse_endpoint_id(&payload.endpoint_id)?;
    let updated_by = require_nonempty("updated_by", &payload.updated_by)?;
    let idempotency_key = super::resolve_idempotency_key(payload.idempotency_key)?;
    // New-ref variant: a caller-supplied NEW `webhook_secret_ref` (raw
    // `secret://` URI, provisioned operator-side) is recorded by the server,
    // which bumps the endpoint generation. With no ref the server refuses
    // (501) — it neither mints nor can prove an operator-side rotation. The
    // server validates the ref shape, so malformed input surfaces as a 400.
    let ep = store
        .rotate_messaging_webhook_secret_to_ref(
            &env_id,
            endpoint_id,
            updated_by,
            payload.webhook_secret_ref,
            idempotency_key,
        )
        .map_err(map_store_err_preserving_noun)?;
    Ok(OpOutcome::new(
        "messaging.endpoint",
        "rotate-webhook-secret",
        serde_json::to_value(super::messaging::EndpointSummary::from(&env_id, &ep))
            .expect("EndpointSummary is json-safe"),
    ))
}

// ---------------------------------------------------------------------------
// trust-root: bootstrap, add, remove
// ---------------------------------------------------------------------------

fn remote_trust_root_bootstrap(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
    env_id: Option<String>,
) -> Result<OpOutcome, OpError> {
    let payload =
        env_id.map(|id| super::trust_root::TrustRootBootstrapPayload { environment_id: id });
    let payload = resolve_payload::<super::trust_root::TrustRootBootstrapPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let seed = store
        .bootstrap_trust_root(&env_id)
        .map_err(map_store_err_preserving_noun)?;
    Ok(OpOutcome::new(
        "trust-root",
        "bootstrap",
        super::trust_root::trust_root_seed_to_wire(&env_id, &seed),
    ))
}

fn remote_trust_root_add(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
    args: super::dispatch::TrustRootAddArgs,
) -> Result<OpOutcome, OpError> {
    let payload = match (args.env_id, args.key_id) {
        (Some(env_id), Some(key_id)) => Some(super::trust_root::TrustRootAddPayload {
            environment_id: env_id,
            key_id,
            public_key_pem: args.public_key_pem,
            public_key_file: args.public_key_file,
        }),
        _ => None,
    };
    let payload = resolve_payload::<super::trust_root::TrustRootAddPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let public_key_pem = super::trust_root::resolve_pem(&payload)?;
    let idem = super::mint_idempotency_key();
    let outcome = store
        .add_trusted_key(&env_id, payload.key_id, public_key_pem, idem)
        .map_err(map_store_err_preserving_noun)?;
    Ok(OpOutcome::new(
        "trust-root",
        "add",
        super::trust_root::trust_root_add_outcome_to_wire(&env_id, &outcome),
    ))
}

fn remote_trust_root_remove(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
    args: super::dispatch::TrustRootRemoveArgs,
) -> Result<OpOutcome, OpError> {
    let payload = match (args.env_id, args.key_id) {
        (Some(env_id), Some(key_id)) => Some(super::trust_root::TrustRootRemovePayload {
            environment_id: env_id,
            key_id,
        }),
        _ => None,
    };
    let payload = resolve_payload::<super::trust_root::TrustRootRemovePayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let idem = super::mint_idempotency_key();
    let outcome = store
        .remove_trusted_key(&env_id, payload.key_id, idem)
        .map_err(map_store_err_preserving_noun)?;
    Ok(OpOutcome::new(
        "trust-root",
        "remove",
        super::trust_root::trust_root_remove_outcome_to_wire(&env_id, &outcome),
    ))
}

/// Remote `env trust-root list`. The trusted-key set comes from
/// `GET /environments/{env_id}/trust-root` (an inherent read on the HTTP
/// store, not on [`EnvironmentMutations`], since trust roots are a separate
/// document); the JSON projection is shared with the local path via
/// [`super::trust_root::list_outcome`].
fn remote_trust_root_list(
    store: &HttpEnvironmentStore,
    env_id: &str,
) -> Result<OpOutcome, OpError> {
    let env_id = parse_env_id(env_id)?;
    let keys = store
        .load_trust_root_keys(&env_id)
        .map_err(map_store_err_preserving_noun)?;
    Ok(super::trust_root::list_outcome(&env_id, &keys))
}

// ===========================================================================
// env apply: manifest-driven whole-env document reconcile over a remote store
// ===========================================================================

/// Fail-closed gate: refuse every manifest section a control-plane store
/// cannot own, BEFORE any mutation, so the operator fixes them all in one
/// round trip rather than discovering them mid-apply.
fn reject_unsupported_remote_sections(manifest: &EnvManifest) -> Result<(), OpError> {
    // Secret VALUES never reach a control-plane store: there is no server
    // secrets plane (the value plane is operator-local, bridged into the
    // runtime at reconcile). Provision them operator-side and omit `secrets[]`.
    if !manifest.secrets.is_empty() {
        return Err(OpError::InvalidArgument(
            "`secrets[]` cannot be applied over a remote --store-url store: the \
             control-plane store does not custody secret values. Provision them in your \
             own secrets plane, then re-run with a manifest that omits `secrets[]`"
                .to_string(),
        ));
    }
    // Pack/extension binding answer files live on the apply host and cannot
    // travel to a remote store. Bindings WITHOUT an `answers_ref` apply fine.
    if let Some(p) = manifest.packs.iter().find(|p| p.answers_ref.is_some()) {
        return Err(OpError::InvalidArgument(format!(
            "pack binding for slot `{}` carries a local `answers_ref` that cannot be applied \
             over a remote --store-url store. Apply the answer file operator-side, or drop \
             `answers_ref` from the binding",
            p.slot
        )));
    }
    if let Some(e) = manifest.extensions.iter().find(|e| e.answers_ref.is_some()) {
        return Err(OpError::InvalidArgument(format!(
            "extension binding `{}` carries a local `answers_ref` that cannot be applied over \
             a remote --store-url store. Apply the answer file operator-side, or drop \
             `answers_ref` from the binding",
            e.kind
        )));
    }
    // Telegram-class endpoints need a webhook secret the manifest cannot carry
    // (no `webhook_secret_ref` field) and the control-plane store never mints
    // (R2). Add them explicitly with `op messaging endpoint add
    // --webhook-secret-ref` against the remote store.
    if let Some(ep) = manifest
        .messaging_endpoints
        .iter()
        .find(|ep| greentic_deploy_spec::engine::messaging::is_telegram_class(&ep.provider_type))
    {
        return Err(OpError::InvalidArgument(format!(
            "telegram-class endpoint `{}` cannot be applied over a remote --store-url store via \
             manifest (the manifest carries no webhook_secret_ref, and the control-plane store \
             never mints one). Add it explicitly with `op messaging endpoint add \
             --webhook-secret-ref <ref>`",
            ep.name
        )));
    }
    // Every bundle revision must be pullable + verifiable by a remote worker: a
    // registry `bundle_source_uri` plus a pinned, non-placeholder
    // `bundle_digest`. A local `bundle_path` has no meaning server-side.
    for b in &manifest.bundles {
        require_remote_bundle_pointers(b)?;
    }
    Ok(())
}

/// A `bundle_digest` a remote worker can verify: real `sha256:` material, not
/// the local-serve placeholder (`sha256:00`).
fn remote_pullable_digest(declared: Option<&str>) -> bool {
    // Defers to the local pipeline's `digest_is_real` so the placeholder
    // sentinel (`sha256:00`) has a single definition across both paths.
    declared.is_some_and(super::env_apply::digest_is_real)
}

/// Require registry pull pointers on every revision of `b` (single- or
/// multi-revision form). Mirrors the constraint R1 enforced on remote
/// `revisions stage`.
fn require_remote_bundle_pointers(b: &ManifestBundle) -> Result<(), OpError> {
    fn check(label: String, source_uri: Option<&str>, digest: Option<&str>) -> Result<(), OpError> {
        if source_uri.map(str::trim).is_none_or(|u| u.is_empty()) {
            return Err(OpError::InvalidArgument(format!(
                "{label} needs a registry `bundle_source_uri` to apply over a remote \
                 --store-url store (a local `bundle_path` cannot be extracted server-side): \
                 push the bundle to a registry and pin its oci:// ref"
            )));
        }
        if !remote_pullable_digest(digest) {
            return Err(OpError::InvalidArgument(format!(
                "{label} needs a real pinned `bundle_digest` (sha256:…) to apply over a remote \
                 --store-url store — a remote worker cannot verify an unpinned pull"
            )));
        }
        Ok(())
    }
    match &b.revisions {
        Some(revisions) => {
            for rev in revisions {
                check(
                    format!("bundle `{}` revision `{}`", b.bundle_id, rev.name),
                    rev.bundle_source_uri.as_deref(),
                    rev.bundle_digest.as_deref(),
                )?;
            }
            Ok(())
        }
        None => check(
            format!("bundle `{}`", b.bundle_id),
            b.bundle_source_uri.as_deref(),
            b.bundle_digest.as_deref(),
        ),
    }
}

/// One desired revision for a bundle, resolved from the manifest: the traffic
/// weight, the registry pull ref, the integrity digest, and the drain window.
/// A named struct (vs a 5-tuple of three `String`s) keeps `source_uri` and
/// `digest` from being transposed at the call sites.
struct DesiredRevision {
    name: String,
    weight_bps: u32,
    source_uri: String,
    digest: String,
    drain_seconds: u32,
}

/// True when the deployment's live traffic split already equals the desired
/// revision set — the convergence skip that makes apply re-runnable without
/// relying on the bounded server replay ledger.
fn deployment_converged_remote(
    env: &greentic_deploy_spec::Environment,
    deployment_id: DeploymentId,
    desired: &[DesiredRevision],
) -> bool {
    // Multiset equality of `(weight_bps, source_uri, digest)` between the live
    // split and the desired set: every live entry must resolve to a real-digest
    // revision, and a missing/placeholder digest fails convergence (a false
    // "converged" is the dangerous direction — it would skip applying the split).
    let Some(split) = env
        .traffic_splits
        .iter()
        .find(|s| s.deployment_id == deployment_id)
    else {
        return false;
    };
    if split.entries.len() != desired.len() {
        return false;
    }
    let mut live: Vec<(u32, Option<&str>, &str)> = Vec::with_capacity(split.entries.len());
    for entry in &split.entries {
        let Some(rev) = env
            .revisions
            .iter()
            .find(|r| r.revision_id == entry.revision_id)
        else {
            return false;
        };
        if !remote_pullable_digest(Some(rev.bundle_digest.as_str())) {
            return false;
        }
        live.push((
            entry.weight_bps,
            rev.bundle_source_uri.as_deref(),
            rev.bundle_digest.as_str(),
        ));
    }
    let mut want: Vec<(u32, Option<&str>, &str)> = desired
        .iter()
        .map(|d| (d.weight_bps, Some(d.source_uri.as_str()), d.digest.as_str()))
        .collect();
    live.sort_unstable();
    want.sort_unstable();
    live == want
}

/// Diff a manifest bundle entry against a live deployment; returns the
/// `update_bundle` payload when any declared metadata (route binding, status,
/// revenue share, config overrides) differs from the live deployment, or `None`
/// when nothing changed. A manifest field left unset means "leave untouched"
/// (never a diff). Without this, a route/tenant change on an existing deployment
/// would be silently dropped while a new revision still shifted traffic — a
/// success report serving stale routing.
fn bundle_metadata_update(
    b: &ManifestBundle,
    dep: &greentic_deploy_spec::BundleDeployment,
) -> Option<UpdateBundlePayload> {
    let route_binding = b
        .route_binding
        .clone()
        .map(super::bundles::into_route_binding)
        .filter(|rb| *rb != dep.route_binding);
    let status = b.status.filter(|s| *s != dep.status);
    let revenue_share = b
        .revenue_share
        .as_ref()
        .map(|s| super::bundles::convert_revenue_share(s))
        .filter(|rs| *rs != dep.revenue_share);
    let config_overrides = b
        .config_overrides
        .clone()
        .filter(|co| *co != dep.config_overrides);
    if route_binding.is_none()
        && status.is_none()
        && revenue_share.is_none()
        && config_overrides.is_none()
    {
        return None;
    }
    Some(UpdateBundlePayload {
        deployment_id: dep.deployment_id,
        status,
        route_binding,
        revenue_share,
        config_overrides,
    })
}

/// The planned steps of a remote env apply plus a count of how many represent
/// *drift* — a change apply would make. [`Plan::change`] records a mutating step
/// (counts as drift), [`Plan::noop`] records an already-converged step (does
/// not). The `--check` convergence verdict is simply `drift == 0`. Mirrors the
/// local pipeline's [`super::env_apply::ApplyAction::counts_as_drift`] without
/// coupling to its typed steps.
#[derive(Default)]
struct Plan {
    steps: Vec<Value>,
    drift: usize,
}

impl Plan {
    /// Record a step that changes remote state (drift).
    fn change(&mut self, detail: Value) {
        self.drift += 1;
        self.steps.push(detail);
    }
    /// Record an already-converged step (not drift).
    fn noop(&mut self, detail: Value) {
        self.steps.push(detail);
    }
}

/// Resolve the manifest host-config into an [`UpdateEnvironmentPayload`] and
/// report whether any declared field differs from the live env (the `--check`
/// drift signal). Parsing runs in every mode, so a malformed `listen_addr` /
/// `public_base_url` is caught by `--check` and `--dry-run`, not only by apply.
/// A manifest field left unset means "leave untouched" (never a diff). Mirrors
/// the local pipeline's host-config diff ([`super::env_apply`]), except the
/// remote `update_environment` carries `public_base_url` in the same payload.
fn resolve_host_config_update(
    m: &super::env_manifest::ManifestEnvironment,
    env: &greentic_deploy_spec::Environment,
) -> Result<(UpdateEnvironmentPayload, bool), OpError> {
    let public_base_url = match &m.public_base_url {
        Some(raw) => Some(super::env::parse_public_base_url(raw)?),
        None => None,
    };
    let listen_addr = match &m.listen_addr {
        Some(raw) => Some(
            raw.parse::<std::net::SocketAddr>()
                .map_err(|e| OpError::InvalidArgument(format!("listen_addr {raw:?}: {e}")))?,
        ),
        None => None,
    };
    let hc = &env.host_config;
    let differs = m.name.as_ref().is_some_and(|n| *n != env.name)
        || m.region
            .as_ref()
            .is_some_and(|r| hc.region.as_deref() != Some(r.as_str()))
        || m.tenant_org_id
            .as_ref()
            .is_some_and(|t| hc.tenant_org_id.as_deref() != Some(t.as_str()))
        || listen_addr.is_some_and(|la| hc.listen_addr != Some(la))
        || public_base_url
            .as_deref()
            .is_some_and(|u| hc.public_base_url.as_deref() != Some(u))
        || m.gui_enabled.is_some_and(|g| hc.gui_enabled != Some(g));
    let payload = UpdateEnvironmentPayload {
        name: m.name.clone(),
        region: FieldUpdate::from_option(m.region.clone()),
        tenant_org_id: FieldUpdate::from_option(m.tenant_org_id.clone()),
        listen_addr: match listen_addr {
            Some(la) => FieldUpdate::Set(la),
            None => FieldUpdate::Keep,
        },
        public_base_url: match public_base_url {
            Some(u) => FieldUpdate::Set(u),
            None => FieldUpdate::Keep,
        },
        gui_enabled: FieldUpdate::from_option(m.gui_enabled),
    };
    Ok((payload, differs))
}

/// `gtc op env apply --answers <manifest> --store-url <url>`.
///
/// The remote peer of [`super::env_apply::apply`]. The local pipeline writes
/// secret VALUES into the operator-local dev store and resolves bundle
/// artifacts from local files; a control-plane store custodies only the env
/// DOCUMENT, so this composes the already-remote typed verbs (env update,
/// trust-root, bindings, bundle add, revision stage/warm, traffic, messaging)
/// and FAIL-CLOSED refuses every section it cannot own (see
/// [`reject_unsupported_remote_sections`]). The runtime ROLLOUT (pulling
/// images, rolling pods) is a separate concern (`env reconcile` / the runtime
/// consuming the store), not part of apply.
///
/// Re-runnability comes from CONVERGENCE, not from stable idempotency keys
/// against the bounded server replay ledger: apply reads current env state and
/// skips a deployment already at its desired revision set, an endpoint that
/// already exists, and a binding already bound. Genuine stages mint FRESH
/// revision ids — a stable id would collide (`DuplicateRevision`) on a re-apply
/// once the ledger evicts the original key. Idempotency keys are minted per
/// mutation (audit-replay metadata only). Remote apply is non-interactive: it
/// never prompts (secrets are rejected, not collected) and executes without the
/// local TTY confirmation — the `--store-url` + `--answers` invocation is the
/// explicit intent.
///
/// Three modes (the [`ApplyMode`] from `opts`): `Apply` mutates; `DryRun` walks
/// the same read-only plan and reports it without mutating (always succeeds);
/// `Check` is the CI convergence gate — it walks the plan read-only and returns
/// [`OpError::Conflict`] when any step is drift (a change apply would make),
/// else success. Every declared section is diffed against live state: pack and
/// extension bindings by `kind` + `pack_ref` (a ref/version change is drift, not
/// a converged `skip-bound`), and trust-root via the
/// [`EnvironmentMutations::trust_root_is_seeded`] read probe (an unseeded env is
/// drift, not a silent green).
fn remote_env_apply(
    store: &dyn EnvironmentMutations,
    flags: &OpFlags,
    opts: ApplyOptions,
) -> Result<OpOutcome, OpError> {
    let manifest_path = flags.answers.clone().ok_or_else(|| {
        OpError::InvalidArgument(
            "env apply requires `--answers <manifest.json>` (a greentic.env-manifest.v1 \
             document; see `gtc op env apply --schema`)"
                .to_string(),
        )
    })?;
    let manifest: EnvManifest = super::load_answers(&manifest_path)?;
    manifest.validate_shape()?;
    reject_unsupported_remote_sections(&manifest)?;

    // `Check` and `DryRun` both walk the plan without mutating; only `Apply`
    // writes. `Check` additionally fails when any step is drift (see the verdict
    // at the end).
    let read_only = opts.mode != ApplyMode::Apply;

    let env_id = parse_env_id(&manifest.environment.id)?;
    let updated_by = opts
        .updated_by
        .clone()
        .unwrap_or_else(|| "env-apply".to_string());

    // A named env must already exist on the remote store — apply reconciles, it
    // never creates (the local-only `local` bootstrap has no remote peer).
    let env = store.load_environment(&env_id).map_err(|e| match e {
        StoreError::NotFound(_) => OpError::NotFound(format!(
            "environment `{env_id}` not found on the remote store — create it first \
             (`gtc op env create {env_id} --store-url <url>`) before applying"
        )),
        other => map_store_err_preserving_noun(other),
    })?;

    let mut plan = Plan::default();

    // -- 1. environment host config / public base url (upsert; never clears) --
    // Diff against the live env so `--check` reports drift only on a real change
    // (and apply skips a redundant no-op write + audit record).
    let m = &manifest.environment;
    if m.public_base_url.is_some() || m.declares_host_config() {
        let (payload, differs) = resolve_host_config_update(m, &env)?;
        if differs {
            plan.change(
                json!({"section": "environment", "action": "reconcile", "id": env_id.as_str()}),
            );
            if !read_only {
                store
                    .update_environment(&env_id, payload)
                    .map_err(map_store_err_preserving_noun)?;
            }
        } else {
            plan.noop(
                json!({"section": "environment", "action": "current", "id": env_id.as_str()}),
            );
        }
    }

    // -- 2. trust root (diff via the read probe; seed when absent) -----------
    // `trust_root_is_seeded` reads the remote trust root so an unseeded env is
    // real drift, not a silent green. Seeding is idempotent on apply.
    if manifest.trust_root.is_some() {
        if store
            .trust_root_is_seeded(&env_id)
            .map_err(map_store_err_preserving_noun)?
        {
            plan.noop(json!({"section": "trust-root", "action": "seeded"}));
        } else {
            plan.change(json!({"section": "trust-root", "action": "seed-if-absent"}));
            if !read_only {
                store
                    .seed_trust_root_if_absent(&env_id)
                    .map_err(map_store_err_preserving_noun)?;
            }
        }
    }

    // -- 3. env-pack bindings (answer-less; add / update / skip) -------------
    // Diff `kind` + `pack_ref` against the live binding (mirrors the local
    // pipeline): a changed ref/version is drift routed through `update`, not a
    // converged `skip-bound`. `answers_ref` is always None here (rejected up
    // front), so it never enters the diff.
    for p in &manifest.packs {
        let existing = env.pack_for_slot(p.slot);
        if let Some(b) = existing
            && b.kind.to_string() == p.kind
            && b.pack_ref.as_str() == p.pack_ref
        {
            plan.noop(
                json!({"section": "pack", "slot": p.slot.to_string(), "action": "skip-bound"}),
            );
            continue;
        }
        let action = if existing.is_some() { "update" } else { "add" };
        plan.change(json!({"section": "pack", "slot": p.slot.to_string(), "action": action}));
        if !read_only {
            let payload = super::env_packs::EnvPackBindingPayload {
                environment_id: env_id.as_str().to_string(),
                slot: p.slot,
                kind: p.kind.clone(),
                pack_ref: p.pack_ref.clone(),
                answers_ref: None,
                idempotency_key: None,
            };
            let binding = super::env_packs::build_binding(&payload, 0, None)?;
            if existing.is_some() {
                store
                    .update_pack_binding(&env_id, p.slot, binding, super::mint_idempotency_key())
                    .map_err(map_store_err_preserving_noun)?;
            } else {
                store
                    .add_pack_binding(&env_id, binding, super::mint_idempotency_key())
                    .map_err(map_store_err_preserving_noun)?;
            }
        }
    }

    // -- 4. bundles: reconcile metadata, then converge revisions -------------
    for b in &manifest.bundles {
        let customer_id = super::bundles::resolve_customer_id(&env_id, b.customer_id.clone())?;
        let existing = env
            .bundles
            .iter()
            .find(|d| d.bundle_id.as_str() == b.bundle_id && d.customer_id == customer_id);

        let revs: Vec<DesiredRevision> = match &b.revisions {
            Some(revisions) => {
                let weights = super::env_manifest::compute_effective_weights_bps(revisions);
                revisions
                    .iter()
                    .zip(weights)
                    .map(|(r, weight_bps)| DesiredRevision {
                        name: r.name.clone(),
                        weight_bps,
                        source_uri: r.bundle_source_uri.clone().unwrap_or_default(),
                        digest: r.bundle_digest.clone().unwrap_or_default(),
                        drain_seconds: r
                            .drain_seconds
                            .unwrap_or_else(super::revisions::default_drain_seconds),
                    })
                    .collect()
            }
            None => vec![DesiredRevision {
                name: "default".to_string(),
                weight_bps: super::deploy::FULL_TRAFFIC_BPS,
                source_uri: b.bundle_source_uri.clone().unwrap_or_default(),
                digest: b.bundle_digest.clone().unwrap_or_default(),
                drain_seconds: super::revisions::default_drain_seconds(),
            }],
        };

        let deployment_id: Option<DeploymentId> = match existing {
            Some(d) => {
                // Reconcile drifted deployment metadata (route / status /
                // revenue-share / config); silently shifting a new revision
                // through a stale route would be a misleading success.
                match bundle_metadata_update(b, d) {
                    Some(update) => {
                        plan.change(json!({
                            "section": "bundle", "bundle_id": b.bundle_id,
                            "action": "update-metadata",
                            "deployment_id": d.deployment_id.to_string()
                        }));
                        if !read_only {
                            store
                                .update_bundle(&env_id, update, super::mint_idempotency_key())
                                .map_err(map_store_err_preserving_noun)?;
                        }
                    }
                    None => plan.noop(json!({
                        "section": "bundle", "bundle_id": b.bundle_id, "action": "reuse",
                        "deployment_id": d.deployment_id.to_string()
                    })),
                }
                Some(d.deployment_id)
            }
            None => {
                plan.change(
                    json!({"section": "bundle", "bundle_id": b.bundle_id, "action": "add"}),
                );
                if read_only {
                    None
                } else {
                    let revenue_share = super::bundles::convert_revenue_share(
                        &b.revenue_share
                            .clone()
                            .unwrap_or_else(super::bundles::default_revenue_share),
                    );
                    let route_binding = Some(super::bundles::into_route_binding(
                        b.route_binding.clone().unwrap_or_default(),
                    ));
                    let dep = store
                        .add_bundle(
                            &env_id,
                            AddBundlePayload {
                                bundle_id: BundleId::new(&b.bundle_id),
                                customer_id: customer_id.clone(),
                                revenue_share,
                                route_binding,
                                authorization_ref: Some(
                                    super::bundles::default_authorization_ref()
                                        .to_string_lossy()
                                        .into_owned(),
                                ),
                                config_overrides: b.config_overrides.clone().unwrap_or_default(),
                            },
                            super::mint_idempotency_key(),
                        )
                        .map_err(map_store_err_preserving_noun)?;
                    Some(dep.deployment_id)
                }
            }
        };

        // Convergence: skip stage/warm/traffic when the live split already
        // matches the desired (weight, source_uri, digest) set.
        if let Some(dep_id) = deployment_id
            && deployment_converged_remote(&env, dep_id, &revs)
        {
            plan.noop(json!({
                "section": "revision", "bundle_id": b.bundle_id, "action": "converged"
            }));
            continue;
        }

        let mut traffic_entries: Vec<TrafficSplitEntry> = Vec::with_capacity(revs.len());
        for rev in revs {
            plan.change(json!({
                "section": "revision", "bundle_id": b.bundle_id, "revision": rev.name,
                "action": "stage", "weight_bps": rev.weight_bps
            }));
            if !read_only {
                let deployment_id =
                    deployment_id.expect("apply mode resolves a deployment id before staging");
                // Mint a fresh revision id per genuine stage: a stable id would
                // collide (`DuplicateRevision`) on re-apply once the server
                // replay ledger evicts the original key.
                let revision_id = crate::environment::mint_revision_id();
                let staged = store
                    .stage_revision(
                        &env_id,
                        StageRevisionPayload {
                            revision_id,
                            deployment_id,
                            bundle_digest: rev.digest,
                            bundle_source_uri: Some(rev.source_uri),
                            // Pack metadata is derivable only from the local
                            // artifact; a remote pin-pointer stage records the
                            // pull coordinate + integrity pin and leaves it empty
                            // (the bundle is self-describing once pulled).
                            pack_list: Vec::new(),
                            pack_list_lock_ref: std::path::PathBuf::new(),
                            pack_config_refs: Vec::new(),
                            config_digest: super::revisions::default_config_digest(),
                            signature_sidecar_ref: super::revisions::default_signature_sidecar_ref(
                            ),
                            drain_seconds: rev.drain_seconds,
                        },
                        super::mint_idempotency_key(),
                    )
                    .map_err(map_store_err_preserving_noun)?;
                store
                    .warm_revision(
                        &env_id,
                        WarmRevisionPayload {
                            revision_id,
                            health_gate: Ok(()),
                            expected_lifecycle: staged.lifecycle,
                        },
                        super::mint_idempotency_key(),
                    )
                    .map_err(map_store_err_preserving_noun)?;
                traffic_entries.push(TrafficSplitEntry {
                    revision_id,
                    weight_bps: rev.weight_bps,
                });
            }
        }

        plan.change(json!({
            "section": "traffic", "bundle_id": b.bundle_id, "entries": traffic_entries.len()
        }));
        if !read_only {
            let deployment_id =
                deployment_id.expect("apply mode resolves a deployment id before traffic");
            store
                .set_traffic_split(
                    &env_id,
                    SetTrafficSplitPayload {
                        deployment_id,
                        entries: traffic_entries,
                        updated_by: updated_by.clone(),
                        authorization_ref: Some(
                            super::traffic::default_authorization_ref()
                                .to_string_lossy()
                                .into_owned(),
                        ),
                    },
                    super::mint_idempotency_key(),
                )
                .map_err(super::traffic::map_traffic_store_err)?;
        }
    }

    // -- 5. extension bindings (answer-less; add / update / skip) ------------
    // Keyed by (kind.path(), instance_id); diff the full `kind` (path@version)
    // + `pack_ref` (mirrors the local pipeline) so a version/ref change under
    // the same path is drift routed through `update`, not a converged skip.
    for e in &manifest.extensions {
        let descriptor = greentic_deploy_spec::PackDescriptor::try_new(&e.kind).map_err(|err| {
            OpError::InvalidArgument(format!("extensions[] kind `{}`: {err}", e.kind))
        })?;
        let existing = env
            .extensions
            .iter()
            .find(|b| b.kind.path() == descriptor.path() && b.instance_id == e.instance_id);
        if let Some(b) = existing
            && b.kind.to_string() == e.kind
            && b.pack_ref.as_str() == e.pack_ref
        {
            plan.noop(json!({"section": "extension", "kind": e.kind, "action": "skip-bound"}));
            continue;
        }
        let action = if existing.is_some() { "update" } else { "add" };
        plan.change(json!({"section": "extension", "kind": e.kind, "action": action}));
        if !read_only {
            let payload = super::extensions::ExtensionBindingPayload {
                environment_id: env_id.as_str().to_string(),
                kind: e.kind.clone(),
                pack_ref: e.pack_ref.clone(),
                instance_id: e.instance_id.clone(),
                answers_ref: None,
                idempotency_key: None,
            };
            let binding = super::extensions::build_binding(&payload, 0, None)?;
            if existing.is_some() {
                let key = super::extensions::build_key(&e.kind, &e.instance_id)?;
                store
                    .update_extension_binding(&env_id, key, binding, super::mint_idempotency_key())
                    .map_err(map_store_err_preserving_noun)?;
            } else {
                store
                    .add_extension_binding(&env_id, binding, super::mint_idempotency_key())
                    .map_err(map_store_err_preserving_noun)?;
            }
        }
    }

    // -- 6. messaging endpoints (non-telegram; add → link → welcome) ---------
    for ep in &manifest.messaging_endpoints {
        // Reuse an existing endpoint by (provider_type, name): a re-add would
        // hit `EndpointAlreadyExists`. Links are additive (link only un-linked
        // bundles); welcome is set only when it differs from the live value.
        let matched = env
            .messaging_endpoints
            .iter()
            .find(|m| m.provider_type == ep.provider_type && m.display_name == ep.name);
        let endpoint_id: Option<MessagingEndpointId> = match matched {
            Some(m) => {
                plan.noop(json!({"section": "endpoint", "name": ep.name, "action": "reuse"}));
                Some(m.endpoint_id)
            }
            None => {
                plan.change(json!({"section": "endpoint", "name": ep.name, "action": "add"}));
                if read_only {
                    None
                } else {
                    let endpoint = store
                        .add_messaging_endpoint(
                            &env_id,
                            AddMessagingEndpointPayload {
                                provider_id: ep.name.clone(),
                                provider_type: ep.provider_type.clone(),
                                display_name: ep.name.clone(),
                                secret_refs: ep.secret_refs.clone(),
                                webhook_secret_ref: None,
                                updated_by: updated_by.clone(),
                            },
                            super::mint_idempotency_key(),
                        )
                        .map_err(map_store_err_preserving_noun)?;
                    Some(endpoint.endpoint_id)
                }
            }
        };

        for link in &ep.links {
            let already_linked = matched
                .is_some_and(|m| m.linked_bundles.iter().any(|x| x.as_str() == link.as_str()));
            if already_linked {
                plan.noop(json!({
                    "section": "endpoint-link", "name": ep.name, "bundle_id": link,
                    "action": "skip-linked"
                }));
                continue;
            }
            plan.change(json!({
                "section": "endpoint-link", "name": ep.name, "bundle_id": link, "action": "link"
            }));
            if !read_only {
                let endpoint_id = endpoint_id.expect("apply mode resolves an endpoint id");
                store
                    .link_messaging_bundle(
                        &env_id,
                        endpoint_id,
                        parse_bundle_id(link)?,
                        updated_by.clone(),
                        super::mint_idempotency_key(),
                    )
                    .map_err(map_store_err_preserving_noun)?;
            }
        }

        if let Some(wf) = &ep.welcome_flow {
            let current_equal = matched.is_some_and(|m| {
                m.welcome_flow.as_ref().is_some_and(|cur| {
                    cur.bundle_id.as_str() == wf.bundle_id
                        && cur.pack_id.as_str() == wf.pack_id
                        && cur.flow_id == wf.flow_id
                })
            });
            if current_equal {
                plan.noop(json!({
                    "section": "endpoint-welcome", "name": ep.name, "action": "skip-current"
                }));
            } else {
                plan.change(
                    json!({"section": "endpoint-welcome", "name": ep.name, "action": "set"}),
                );
                if !read_only {
                    let endpoint_id = endpoint_id.expect("apply mode resolves an endpoint id");
                    store
                        .set_messaging_welcome_flow(
                            &env_id,
                            SetMessagingWelcomeFlowPayload {
                                endpoint_id,
                                bundle_id: parse_bundle_id(&wf.bundle_id)?,
                                pack_id: PackId::new(&wf.pack_id),
                                flow_id: wf.flow_id.clone(),
                                updated_by: updated_by.clone(),
                            },
                            super::mint_idempotency_key(),
                        )
                        .map_err(map_store_err_preserving_noun)?;
                }
            }
        }
    }

    // `--check` convergence verdict: fail (non-zero) when any step is drift.
    if opts.mode == ApplyMode::Check && plan.drift > 0 {
        return Err(OpError::Conflict(format!(
            "environment `{}` is not converged: {} pending change(s) over the remote store — run \
             `gtc op env apply --answers <manifest> --store-url <url>` to reconcile (see the step \
             list)",
            env_id.as_str(),
            plan.drift
        )));
    }
    Ok(OpOutcome::new(
        "env",
        "apply",
        json!({
            "environment_id": env_id.as_str(),
            "mode": opts.mode.as_str(),
            "pending_changes": plan.drift,
            "steps": plan.steps,
        }),
    ))
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::environment::{AuthMethod, HttpEnvironmentStore};
    use clap::Parser;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::path::PathBuf;
    use std::sync::Arc;

    // -----------------------------------------------------------------------
    // resolve_remote_target: URL/token origin pairing (anti-credential-leak)
    // -----------------------------------------------------------------------

    #[test]
    fn flag_url_never_inherits_env_token() {
        // A flag URL with NO flag token must NOT pick up the env token —
        // otherwise a prod GREENTIC_STORE_TOKEN leaks to an ad-hoc endpoint.
        let (url, token) = resolve_remote_target(
            Some("https://flag.example".to_string()),
            None,
            Some("https://env.example".to_string()),
            Some("env-secret".to_string()),
        );
        assert_eq!(url.as_deref(), Some("https://flag.example"));
        assert_eq!(token, None, "env token must not pair with a flag URL");
    }

    #[test]
    fn flag_url_keeps_explicit_flag_token() {
        let (url, token) = resolve_remote_target(
            Some("https://flag.example".to_string()),
            Some("flag-secret".to_string()),
            None,
            Some("env-secret".to_string()),
        );
        assert_eq!(url.as_deref(), Some("https://flag.example"));
        assert_eq!(token.as_deref(), Some("flag-secret"));
    }

    #[test]
    fn env_url_inherits_env_token_but_flag_token_wins() {
        let (url, token) = resolve_remote_target(
            None,
            None,
            Some("https://env.example".to_string()),
            Some("env-secret".to_string()),
        );
        assert_eq!(url.as_deref(), Some("https://env.example"));
        assert_eq!(token.as_deref(), Some("env-secret"));

        let (_, token) = resolve_remote_target(
            None,
            Some("flag-secret".to_string()),
            Some("https://env.example".to_string()),
            Some("env-secret".to_string()),
        );
        assert_eq!(token.as_deref(), Some("flag-secret"), "flag token wins");
    }

    #[test]
    fn no_url_means_no_remote_target() {
        let (url, token) =
            resolve_remote_target(None, Some("x".to_string()), None, Some("y".to_string()));
        assert_eq!(url, None);
        assert_eq!(token, None);
    }

    // -----------------------------------------------------------------------
    // Minimal mock (same idiom as http_store.rs tests)
    // -----------------------------------------------------------------------

    struct MockServer {
        addr: SocketAddr,
        _handle: std::thread::JoinHandle<()>,
    }

    type CheckFn = Arc<dyn Fn(&str, &str, &[u8]) + Send + Sync>;

    fn start_mock(responses: Vec<(u16, &str)>, check: Option<CheckFn>) -> MockServer {
        let responses: Vec<(u16, String)> = responses
            .into_iter()
            .map(|(s, b)| (s, b.to_string()))
            .collect();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            for (status, body) in responses {
                let (stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream);
                let mut lines: Vec<String> = Vec::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
                    if trimmed.is_empty() {
                        break;
                    }
                    lines.push(trimmed.to_string());
                }
                let content_length: usize = lines
                    .iter()
                    .find(|l| l.to_lowercase().starts_with("content-length:"))
                    .and_then(|l| l.split(':').nth(1))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                let mut req_body = vec![0u8; content_length];
                if content_length > 0 {
                    std::io::Read::read_exact(&mut reader, &mut req_body).unwrap();
                }
                if let Some(ref check_fn) = check {
                    let request_line = lines.first().map(|s| s.as_str()).unwrap_or("");
                    let headers = lines[1..].join("\r\n");
                    check_fn(request_line, &headers, &req_body);
                }
                // Substitute {{IDEMPOTENCY_KEY}} placeholder with the real
                // request header value so audit key correlation passes.
                let body = if body.contains("{{IDEMPOTENCY_KEY}}") {
                    let idem_val = lines
                        .iter()
                        .find(|l| l.to_lowercase().starts_with("idempotency-key:"))
                        .and_then(|l| l.split_once(':').map(|(_, v)| v.trim().to_string()))
                        .unwrap_or_default();
                    body.replace("{{IDEMPOTENCY_KEY}}", &idem_val)
                } else {
                    body
                };
                let status_text = match status {
                    200 => "OK",
                    201 => "Created",
                    _ => "Unknown",
                };
                let response = format!(
                    "HTTP/1.1 {status} {status_text}\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n{body}",
                    body.len()
                );
                let stream_ref = reader.get_mut();
                stream_ref.write_all(response.as_bytes()).unwrap();
                stream_ref.flush().unwrap();
            }
        });
        MockServer {
            addr,
            _handle: handle,
        }
    }

    fn mock_store(addr: SocketAddr, auth: AuthMethod) -> HttpEnvironmentStore {
        HttpEnvironmentStore::new(url::Url::parse(&format!("http://{addr}")).unwrap(), auth)
            .unwrap()
    }

    fn wrap_mutation(domain: serde_json::Value) -> String {
        serde_json::json!({
            "result": domain,
            "etag": "sha256:test",
            "generation": 1,
            "idempotency": {"idempotency": "applied"},
            "audit": {
                "schema": "greentic.audit-event.v1",
                "event_id": "01TEST000000000000000000AA",
                "ts": "2026-06-09T12:00:00Z",
                "actor": {"kind": "operator"},
                "env_id": "local",
                "noun": "test",
                "verb": "test",
                "target": null,
                "authorization": {"decision": "allow", "policy": "local-only", "reason": "test"},
                "result": {"outcome": "ok"},
                "idempotency_key": "{{IDEMPOTENCY_KEY}}"
            }
        })
        .to_string()
    }

    fn no_flags() -> OpFlags {
        OpFlags::default()
    }

    fn env_json() -> serde_json::Value {
        serde_json::json!({
            "schema": "greentic.environment.v1",
            "environment_id": "local",
            "name": "test",
            "host_config": {"env_id": "local"},
            "packs": [],
            "bundles": [],
            "revisions": [],
            "traffic_splits": [],
            "messaging_endpoints": [],
            "extensions": [],
            "revocation": {},
            "retention": {},
            "health": {}
        })
    }

    // -----------------------------------------------------------------------
    // 1. Selection unit test: bad URL + Bearer token assertion
    // -----------------------------------------------------------------------

    #[test]
    fn bad_url_returns_invalid_argument() {
        let cmd = OpCommand::try_parse_from(["op", "--schema", "env", "create", "local"]).unwrap();
        let flags = no_flags();
        let result = dispatch_op_remote("not a url", None, cmd, &flags);
        assert!(
            matches!(result, Err(OpError::InvalidArgument(ref m)) if m.contains("--store-url"))
        );
    }

    #[test]
    fn bearer_token_is_sent() {
        let saw_bearer = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let saw_bearer_clone = saw_bearer.clone();
        let check: CheckFn = Arc::new(move |_req, headers, _body| {
            // reqwest sends header names in lowercase.
            if headers.contains("authorization: Bearer my-secret-token") {
                saw_bearer_clone.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });
        let body = wrap_mutation(env_json());
        let mock = start_mock(vec![(201, &body)], Some(check));
        let store = mock_store(mock.addr, AuthMethod::Bearer("my-secret-token".to_string()));
        // Call a verb via the store directly to assert the header was sent.
        let _ = store.create_environment(
            &EnvId::try_from("local").unwrap(),
            "test".to_string(),
            EnvironmentHostConfig {
                env_id: EnvId::try_from("local").unwrap(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
                gui_enabled: None,
            },
        );
        assert!(
            saw_bearer.load(std::sync::atomic::Ordering::SeqCst),
            "expected Authorization: Bearer header"
        );
    }

    // -----------------------------------------------------------------------
    // 2. Happy-path per noun group
    // -----------------------------------------------------------------------

    #[test]
    fn env_create_happy_path() {
        let body = wrap_mutation(env_json());
        let mock = start_mock(vec![(201, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let outcome = remote_env_create(
            &store,
            &no_flags(),
            Some(super::super::env::EnvCreatePayload {
                environment_id: "local".to_string(),
                name: "test".to_string(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
            }),
        )
        .unwrap();
        assert_eq!(outcome.noun, "env");
        assert_eq!(outcome.op, "create");
    }

    #[test]
    fn env_packs_add_happy_path() {
        let binding = serde_json::json!({
            "slot": "deployer",
            "kind": "greentic.deploy.deployer@1.0.0",
            "pack_ref": "local-deployer",
            "generation": 0,
            "answers_ref": null,
            "previous_binding_ref": null,
        });
        let body = wrap_mutation(binding);
        let mock = start_mock(vec![(201, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            serde_json::json!({
                "environment_id": "local",
                "slot": "deployer",
                "kind": "greentic.deploy.deployer@1.0.0",
                "pack_ref": "local-deployer"
            })
            .to_string(),
        )
        .unwrap();
        let flags = OpFlags {
            schema_only: false,
            answers: Some(tmp.path().to_path_buf()),
        };
        let outcome = remote_env_packs_add(&store, &flags).unwrap();
        assert_eq!(outcome.noun, "env-packs");
        assert_eq!(outcome.op, "add");
    }

    #[test]
    fn extensions_add_happy_path() {
        let binding = serde_json::json!({
            "kind": "greentic.cap.memory-long-term@1.0.0",
            "pack_ref": "memory-pack",
            "instance_id": null,
            "generation": 0,
            "answers_ref": null,
            "previous_binding_ref": null,
        });
        let body = wrap_mutation(binding);
        let mock = start_mock(vec![(201, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            serde_json::json!({
                "environment_id": "local",
                "kind": "greentic.cap.memory-long-term@1.0.0",
                "pack_ref": "memory-pack"
            })
            .to_string(),
        )
        .unwrap();
        let flags = OpFlags {
            schema_only: false,
            answers: Some(tmp.path().to_path_buf()),
        };
        let outcome = remote_extensions_add(&store, &flags).unwrap();
        assert_eq!(outcome.noun, "extensions");
        assert_eq!(outcome.op, "add");
    }

    #[test]
    fn bundles_add_happy_path() {
        let deployment = serde_json::json!({
            "schema": "greentic.bundle-deployment.v1",
            "deployment_id": "01JABC000000000000000000ZZ",
            "env_id": "local",
            "bundle_id": "my-bundle",
            "customer_id": "local-dev",
            "status": "active",
            "current_revisions": [],
            "route_binding": {"hosts": [], "path_prefixes": [], "tenant_selector": {"tenant": "default", "team": "default"}},
            "revenue_share": [{"party_id": "greentic", "basis_points": 10000}],
            "revenue_policy_ref": "revenue.json",
            "created_at": "2026-06-09T12:00:00Z",
            "authorization_ref": "auth.json",
            "config_overrides": {}
        });
        let body = wrap_mutation(deployment);
        let mock = start_mock(vec![(201, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            serde_json::json!({
                "environment_id": "local",
                "bundle_id": "my-bundle",
                "route_binding": {"hosts": [], "path_prefixes": []}
            })
            .to_string(),
        )
        .unwrap();
        let flags = OpFlags {
            schema_only: false,
            answers: Some(tmp.path().to_path_buf()),
        };
        let outcome = remote_bundles_add(&store, &flags).unwrap();
        assert_eq!(outcome.noun, "bundles");
        assert_eq!(outcome.op, "add");
    }

    #[test]
    fn traffic_set_happy_path() {
        let split = serde_json::json!({
            "split": {
                "schema": "greentic.traffic-split.v1",
                "env_id": "local",
                "deployment_id": "01JABC000000000000000000ZZ",
                "bundle_id": "my-bundle",
                "entries": [{"revision_id": "01JABC000000000000000001ZZ", "weight_bps": 10000}],
                "generation": 1,
                "updated_at": "2026-06-09T12:00:00Z",
                "updated_by": "operator",
                "idempotency_key": "01JABC000000000000000099ZZ",
                "authorization_ref": "auth.json",
                "previous_split_ref": null
            },
            "previous_generation": null,
            "new_generation": 1,
            "environment": env_json()
        });
        let body = wrap_mutation(split);
        let mock = start_mock(vec![(200, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);

        let outcome = remote_traffic_set(
            &store,
            &no_flags(),
            Some(super::super::traffic::TrafficSetPayload {
                environment_id: "local".to_string(),
                deployment_id: "01JABC000000000000000000ZZ".to_string(),
                entries: vec![super::super::traffic::TrafficSetEntryPayload {
                    revision_id: "01JABC000000000000000001ZZ".to_string(),
                    weight_bps: Some(10000),
                    weight_percent: None,
                }],
                updated_by: "operator".to_string(),
                idempotency_key: "01JABC000000000000000099ZZ".to_string(),
                authorization_ref: PathBuf::from("auth.json"),
            }),
        )
        .unwrap();
        assert_eq!(outcome.noun, "traffic");
        assert_eq!(outcome.op, "set");
    }

    #[test]
    fn revisions_drain_happy_path() {
        let transition = serde_json::json!({
            "revision": {
                "schema": "greentic.revision.v1",
                "revision_id": "01JABC000000000000000001ZZ",
                "env_id": "local",
                "bundle_id": "my-bundle",
                "deployment_id": "01JABC000000000000000000ZZ",
                "sequence": 1,
                "created_at": "2026-06-09T12:00:00Z",
                "bundle_digest": "sha256:00",
                "pack_list": [],
                "pack_list_lock_ref": "",
                "pack_config_refs": [],
                "config_digest": "sha256:00",
                "signature_sidecar_ref": "rev.sig",
                "lifecycle": "draining",
                "staged_at": "2026-06-09T12:00:00Z",
                "drain_seconds": 30,
                "abort_metrics": []
            },
            "environment": {
                "schema": "greentic.environment.v1",
                "environment_id": "local",
                "name": "test",
                "host_config": {"env_id": "local"},
                "packs": [],
                "bundles": [],
                "revisions": [],
                "traffic_splits": [],
                "messaging_endpoints": [],
                "extensions": [],
                "revocation": {},
                "retention": {},
                "health": {}
            },
            "starting_lifecycle": "ready"
        });
        let body = wrap_mutation(transition);
        let mock = start_mock(vec![(200, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            serde_json::json!({
                "environment_id": "local",
                "revision_id": "01JABC000000000000000001ZZ"
            })
            .to_string(),
        )
        .unwrap();
        let flags = OpFlags {
            schema_only: false,
            answers: Some(tmp.path().to_path_buf()),
        };
        let outcome = remote_revision_transition(&store, &flags, "drain", |s, e, r, k| {
            s.drain_revision(e, r, k)
        })
        .unwrap();
        assert_eq!(outcome.noun, "revisions");
        assert_eq!(outcome.op, "drain");
    }

    #[test]
    fn messaging_add_happy_path() {
        let ep = serde_json::json!({
            "schema": "greentic.messaging-endpoint.v1",
            "env_id": "local",
            "endpoint_id": "01JABC000000000000000001ZZ",
            "provider_id": "telegram-bot",
            "provider_type": "telegram",
            "display_name": "Test Bot",
            "linked_bundles": [],
            "secret_refs": [],
            "generation": 0,
            "created_at": "2026-06-09T12:00:00Z",
            "updated_at": "2026-06-09T12:00:00Z",
            "updated_by": "operator"
        });
        let body = wrap_mutation(ep);
        let mock = start_mock(vec![(201, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);

        let outcome = remote_messaging_add(
            &store,
            &no_flags(),
            Some(super::super::messaging::EndpointAddPayload {
                environment_id: "local".to_string(),
                provider_id: "telegram-bot".to_string(),
                provider_type: "telegram".to_string(),
                display_name: "Test Bot".to_string(),
                secret_refs: vec![],
                // Telegram-class over a remote store requires a caller-supplied ref.
                webhook_secret_ref: Some(
                    "secret://local/default/_/messaging-byo/webhook_secret".to_string(),
                ),
                idempotency_key: None,
                updated_by: "operator".to_string(),
            }),
        )
        .unwrap();
        assert_eq!(outcome.noun, "messaging.endpoint");
        assert_eq!(outcome.op, "add");
    }

    #[test]
    fn messaging_add_telegram_without_ref_rejected_before_round_trip() {
        // No mock responses queued: a telegram-class add with no
        // webhook_secret_ref must fail locally, never reaching the server.
        let mock = start_mock(vec![], None);
        let store = mock_store(mock.addr, AuthMethod::None);

        let err = remote_messaging_add(
            &store,
            &no_flags(),
            Some(super::super::messaging::EndpointAddPayload {
                environment_id: "local".to_string(),
                provider_id: "telegram-bot".to_string(),
                provider_type: "telegram".to_string(),
                display_name: "Test Bot".to_string(),
                secret_refs: vec![],
                webhook_secret_ref: None,
                idempotency_key: None,
                updated_by: "operator".to_string(),
            }),
        )
        .unwrap_err();
        match err {
            OpError::InvalidArgument(ref m) => {
                assert!(m.contains("--webhook-secret-ref"), "got {err:?}")
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn trust_root_add_happy_path() {
        let outcome_json = serde_json::json!({
            "added_key_id": "op-key-1",
            "trusted_key_count": 1
        });
        let body = wrap_mutation(outcome_json);
        let mock = start_mock(vec![(200, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);

        let args = super::super::dispatch::TrustRootAddArgs {
            env_id: Some("local".to_string()),
            key_id: Some("op-key-1".to_string()),
            public_key_pem: Some(
                "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----".to_string(),
            ),
            public_key_file: None,
        };
        let outcome = remote_trust_root_add(&store, &no_flags(), args).unwrap();
        assert_eq!(outcome.noun, "trust-root");
        assert_eq!(outcome.op, "add");
    }

    // -----------------------------------------------------------------------
    // 3. Blocked-verb gating
    // -----------------------------------------------------------------------

    /// A `greentic.revision.v1` JSON value for `rev_id` at `lifecycle`, used to
    /// seed both the `GET /environments` read and the warm transition outcome.
    fn revision_json(rev_id: &str, lifecycle: &str) -> serde_json::Value {
        serde_json::json!({
            "schema": "greentic.revision.v1",
            "revision_id": rev_id,
            "env_id": "local",
            "bundle_id": "fast2flow",
            "deployment_id": rev_id,
            "sequence": 1,
            "created_at": "2026-06-09T12:00:00Z",
            "bundle_digest": "sha256:00",
            "pack_list": [],
            "pack_list_lock_ref": "",
            "pack_config_refs": [],
            "config_digest": "sha256:00",
            "signature_sidecar_ref": "rev.sig",
            "lifecycle": lifecycle,
            "staged_at": "2026-06-09T12:00:00Z",
            "drain_seconds": 30,
            "abort_metrics": []
        })
    }

    /// Write `payload` as a JSON answers file and return flags pointing at it.
    fn answers_flags(payload: serde_json::Value) -> (tempfile::NamedTempFile, OpFlags) {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), payload.to_string()).unwrap();
        let flags = OpFlags {
            schema_only: false,
            answers: Some(tmp.path().to_path_buf()),
        };
        (tmp, flags)
    }

    const TEST_REV_ID: &str = "01JTKW5B4W4Q5Y1CQW93F7S5VH";

    #[test]
    fn revision_stage_pin_pointer_happy_path() {
        // The `--answers` pin-pointer path maps straight onto the store verb;
        // the server persists the pointers and returns the staged revision.
        let body = wrap_mutation(revision_json(TEST_REV_ID, "staged"));
        let mock = start_mock(vec![(201, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let (_tmp, flags) = answers_flags(serde_json::json!({
            "environment_id": "local",
            "deployment_id": TEST_REV_ID,
            "bundle_digest": "sha256:abc",
            "bundle_source_uri": "oci://registry.example/bundle@sha256:abc",
            "pack_list": [],
            "pack_list_lock_ref": "revisions/r/pack-list.lock"
        }));
        let args = super::super::dispatch::RevisionStageArgs {
            env_id: None,
            deployment: None,
            bundle: None,
        };
        let outcome = remote_revision_stage(&store, &flags, args).unwrap();
        assert_eq!(outcome.noun, "revisions");
        assert_eq!(outcome.op, "stage");
    }

    #[test]
    fn revision_stage_local_bundle_rejected() {
        // The direct `--bundle <local.gtbundle>` path can't run against a
        // remote store; it must be rejected before any HTTP call (dummy store
        // refuses connections).
        let result = route_remote(
            &build_dummy_store(),
            &no_flags(),
            OpNoun::Revisions {
                verb: RevisionsVerb::Stage(super::super::dispatch::RevisionStageArgs {
                    env_id: Some("local".to_string()),
                    deployment: Some(TEST_REV_ID.to_string()),
                    bundle: Some(std::path::PathBuf::from("/tmp/never-read.gtbundle")),
                }),
            },
        );
        assert!(
            matches!(result, Err(OpError::InvalidArgument(ref m)) if m.contains("remote") && m.contains("--bundle")),
            "got {result:?}"
        );
    }

    #[test]
    fn revision_stage_rejects_missing_source_uri() {
        // No `bundle_source_uri` → a remote worker can't pull the bundle;
        // reject before any HTTP call (dummy store refuses connections).
        let (_tmp, flags) = answers_flags(serde_json::json!({
            "environment_id": "local",
            "deployment_id": TEST_REV_ID,
            "bundle_digest": "sha256:abc"
        }));
        let args = super::super::dispatch::RevisionStageArgs {
            env_id: None,
            deployment: None,
            bundle: None,
        };
        let result = remote_revision_stage(&build_dummy_store(), &flags, args);
        assert!(
            matches!(result, Err(OpError::InvalidArgument(ref m)) if m.contains("bundle_source_uri")),
            "got {result:?}"
        );
    }

    #[test]
    fn revision_stage_rejects_placeholder_digest() {
        // Real source URI but the placeholder digest default (bundle_digest
        // omitted → "sha256:00") → reject: a remote worker can't verify it.
        let (_tmp, flags) = answers_flags(serde_json::json!({
            "environment_id": "local",
            "deployment_id": TEST_REV_ID,
            "bundle_source_uri": "oci://registry.example/bundle@sha256:abc"
        }));
        let args = super::super::dispatch::RevisionStageArgs {
            env_id: None,
            deployment: None,
            bundle: None,
        };
        let result = remote_revision_stage(&build_dummy_store(), &flags, args);
        assert!(
            matches!(result, Err(OpError::InvalidArgument(ref m)) if m.contains("bundle_digest")),
            "got {result:?}"
        );
    }

    #[test]
    fn revision_stage_honors_stable_idempotency_key_and_revision_id() {
        // A pinned `revision_id` + `idempotency_key` must ride the request
        // verbatim so a lost-response retry replays the original outcome.
        use std::sync::atomic::{AtomicBool, Ordering};
        let stable_key = "01JABC000000000000000000ZZ";
        let seen = Arc::new(AtomicBool::new(false));
        let seen_c = seen.clone();
        let check: CheckFn = Arc::new(move |_req, headers, body| {
            let body_s = String::from_utf8_lossy(body);
            // reqwest lowercases header NAMES; lowercase both sides so the ULID
            // value compares case-insensitively too.
            let needle = format!("idempotency-key: {}", stable_key.to_lowercase());
            if headers.to_lowercase().contains(&needle) && body_s.contains(TEST_REV_ID) {
                seen_c.store(true, Ordering::SeqCst);
            }
        });
        let body = wrap_mutation(revision_json(TEST_REV_ID, "staged"));
        let mock = start_mock(vec![(201, &body)], Some(check));
        let store = mock_store(mock.addr, AuthMethod::None);
        let (_tmp, flags) = answers_flags(serde_json::json!({
            "environment_id": "local",
            "deployment_id": TEST_REV_ID,
            "revision_id": TEST_REV_ID,
            "idempotency_key": stable_key,
            "bundle_digest": "sha256:abc",
            "bundle_source_uri": "oci://registry.example/bundle@sha256:abc"
        }));
        let args = super::super::dispatch::RevisionStageArgs {
            env_id: None,
            deployment: None,
            bundle: None,
        };
        remote_revision_stage(&store, &flags, args).unwrap();
        assert!(
            seen.load(Ordering::SeqCst),
            "stage must send the caller's idempotency key + revision id verbatim"
        );
    }

    #[test]
    fn revision_warm_happy_path() {
        // warm reads the env (GET) to capture the precondition lifecycle, then
        // ships the typed warm (POST). Two sequential responses.
        let mut env = env_json();
        env["revisions"] = serde_json::json!([revision_json(TEST_REV_ID, "staged")]);
        let get_body = serde_json::json!({
            "environment": env,
            "etag": "sha256:test",
            "generation": 1
        })
        .to_string();
        let warm_body = wrap_mutation(serde_json::json!({
            "revision": revision_json(TEST_REV_ID, "ready"),
            "environment": env_json(),
            "starting_lifecycle": "staged"
        }));
        let mock = start_mock(vec![(200, &get_body), (200, &warm_body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let (_tmp, flags) = answers_flags(serde_json::json!({
            "environment_id": "local",
            "revision_id": TEST_REV_ID
        }));
        let outcome = remote_revision_warm(&store, &flags).unwrap();
        assert_eq!(outcome.noun, "revisions");
        assert_eq!(outcome.op, "warm");
    }

    #[test]
    fn revision_warm_revision_not_found() {
        // The env read succeeds but the revision is absent → NotFound, and the
        // warm POST is never sent (single GET response queued).
        let get_body = serde_json::json!({
            "environment": env_json(),
            "etag": "sha256:test",
            "generation": 1
        })
        .to_string();
        let mock = start_mock(vec![(200, &get_body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let (_tmp, flags) = answers_flags(serde_json::json!({
            "environment_id": "local",
            "revision_id": TEST_REV_ID
        }));
        let result = remote_revision_warm(&store, &flags);
        assert!(
            matches!(result, Err(OpError::NotFound(ref m)) if m.contains("not found")),
            "got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // deploy (remote composite): guards, full rollout, idempotent replay
    // -----------------------------------------------------------------------

    #[test]
    fn remote_deploy_rejects_local_bundle_path() {
        // A local `.gtbundle` can't be extracted server-side — reject before
        // any HTTP call (a dead-port store proves no connection is attempted).
        let (_tmp, flags) = answers_flags(serde_json::json!({
            "environment_id": "local",
            "bundle_id": "my-bundle",
            "bundle_path": "/tmp/local.gtbundle"
        }));
        let err = remote_deploy(&build_dummy_store(), &flags, None).unwrap_err();
        assert!(
            matches!(err, OpError::InvalidArgument(ref m) if m.contains("can't be extracted server-side")),
            "got {err:?}"
        );
    }

    #[test]
    fn remote_deploy_requires_bundle_source_uri() {
        let (_tmp, flags) = answers_flags(serde_json::json!({
            "environment_id": "local",
            "bundle_id": "my-bundle",
            "remote_pins": {"bundle_digest": "sha256:abc"}
        }));
        let err = remote_deploy(&build_dummy_store(), &flags, None).unwrap_err();
        assert!(
            matches!(err, OpError::InvalidArgument(ref m) if m.contains("bundle_source_uri")),
            "got {err:?}"
        );
    }

    #[test]
    fn remote_deploy_requires_real_bundle_digest() {
        // The digest must be `sha256:…`-shaped and non-placeholder. Both the
        // placeholder default AND a malformed non-sha256 string are rejected — the
        // latter is what reusing the shared `remote_pullable_digest` tightened (the
        // old inline check would have accepted it).
        for bad in ["sha256:00", "foo"] {
            let (_tmp, flags) = answers_flags(serde_json::json!({
                "environment_id": "local",
                "bundle_id": "my-bundle",
                "bundle_source_uri": "oci://registry.example/b@sha256:abc",
                "remote_pins": {"bundle_digest": bad}
            }));
            let err = remote_deploy(&build_dummy_store(), &flags, None).unwrap_err();
            assert!(
                matches!(err, OpError::InvalidArgument(ref m) if m.contains("bundle_digest")),
                "digest `{bad}` must be rejected, got {err:?}"
            );
        }
    }

    fn deploy_bundle_json() -> serde_json::Value {
        serde_json::json!({
            "schema": "greentic.bundle-deployment.v1",
            "deployment_id": "01JABC000000000000000000ZZ",
            "env_id": "local",
            "bundle_id": "my-bundle",
            "customer_id": "local-dev",
            "status": "active",
            "current_revisions": [],
            "route_binding": {"hosts": [], "path_prefixes": [], "tenant_selector": {"tenant": "default", "team": "default"}},
            "revenue_share": [{"party_id": "greentic", "basis_points": 10000}],
            "revenue_policy_ref": "revenue.json",
            "created_at": "2026-06-09T12:00:00Z",
            "authorization_ref": "auth.json",
            "config_overrides": {}
        })
    }

    fn deploy_split_json() -> serde_json::Value {
        serde_json::json!({
            "schema": "greentic.traffic-split.v1",
            "env_id": "local",
            "deployment_id": "01JABC000000000000000000ZZ",
            "bundle_id": "my-bundle",
            "entries": [{"revision_id": TEST_REV_ID, "weight_bps": 10000}],
            "generation": 1,
            "updated_at": "2026-06-09T12:00:00Z",
            "updated_by": "operator",
            "idempotency_key": "{{IDEMPOTENCY_KEY}}",
            "authorization_ref": "auth.json",
            "previous_split_ref": null
        })
    }

    #[test]
    fn remote_deploy_fresh_happy_path() {
        // Fresh deploy over the remote store: GET env (no bundle) → add → stage
        // → warm → traffic. Five sequential responses, in call order.
        let get_body = serde_json::json!({
            "environment": env_json(),
            "etag": "sha256:test",
            "generation": 1
        })
        .to_string();
        let add_body = wrap_mutation(deploy_bundle_json());
        let stage_body = wrap_mutation(revision_json(TEST_REV_ID, "staged"));
        let warm_body = wrap_mutation(serde_json::json!({
            "revision": revision_json(TEST_REV_ID, "ready"),
            "environment": env_json(),
            "starting_lifecycle": "staged"
        }));
        let traffic_body = wrap_mutation(serde_json::json!({
            "split": deploy_split_json(),
            "previous_generation": null,
            "new_generation": 1,
            "environment": env_json()
        }));
        let mock = start_mock(
            vec![
                (200, &get_body),
                (201, &add_body),
                (201, &stage_body),
                (200, &warm_body),
                (200, &traffic_body),
            ],
            None,
        );
        let store = mock_store(mock.addr, AuthMethod::None);
        let (_tmp, flags) = answers_flags(serde_json::json!({
            "environment_id": "local",
            "bundle_id": "my-bundle",
            "bundle_source_uri": "oci://registry.example/my-bundle@sha256:deadbeef",
            "remote_pins": {"bundle_digest": "sha256:deadbeef"}
        }));
        let outcome = remote_deploy(&store, &flags, None).unwrap();
        assert_eq!(outcome.noun, "deploy");
        assert_eq!(outcome.op, "run");
        assert_eq!(outcome.result["reused_deployment"], false);
        assert_eq!(outcome.result["revision_id"], TEST_REV_ID);
        assert_eq!(outcome.result["status"], "routed");
    }

    #[test]
    fn remote_deploy_idempotent_replay_short_circuits() {
        // A keyed deploy whose split already exists under that key returns the
        // prior outcome after a SINGLE GET — no add/stage/warm/traffic. Only one
        // response is queued, so a second HTTP call would hang the test.
        let mut env = env_json();
        env["bundles"] = serde_json::json!([deploy_bundle_json()]);
        let mut split = deploy_split_json();
        split["idempotency_key"] = serde_json::json!("deploy-key-1");
        env["traffic_splits"] = serde_json::json!([split]);
        let get_body = serde_json::json!({
            "environment": env,
            "etag": "sha256:test",
            "generation": 1
        })
        .to_string();
        let mock = start_mock(vec![(200, &get_body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let (_tmp, flags) = answers_flags(serde_json::json!({
            "environment_id": "local",
            "bundle_id": "my-bundle",
            "bundle_source_uri": "oci://registry.example/my-bundle@sha256:deadbeef",
            "idempotency_key": "deploy-key-1",
            "remote_pins": {"bundle_digest": "sha256:deadbeef"}
        }));
        let outcome = remote_deploy(&store, &flags, None).unwrap();
        assert_eq!(outcome.result["reused_deployment"], true);
        assert_eq!(outcome.result["revision_id"], TEST_REV_ID);
    }

    #[test]
    fn deploy_revision_id_is_deterministic_per_key() {
        // Retry-safety hinges on a STABLE revision id derived from the deploy key
        // (a fresh id would change the stage fingerprint and defeat replay).
        let a = deploy_revision_id(Some("deploy-key-1"));
        assert_eq!(
            a,
            deploy_revision_id(Some("deploy-key-1")),
            "same key must derive the same revision id"
        );
        assert_ne!(
            a,
            deploy_revision_id(Some("deploy-key-2")),
            "different keys must derive different revision ids"
        );
        assert_ne!(
            deploy_revision_id(None),
            deploy_revision_id(None),
            "keyless deploys mint a fresh id each time"
        );
    }

    #[test]
    fn remote_deploy_validates_pins_before_any_mutation() {
        // An invalid pack_list version must be rejected BEFORE any HTTP call, so a
        // bad answers file can't commit a bundle it then can't roll out. A
        // dead-port store proves no connection (hence no mutation) is attempted.
        let (_tmp, flags) = answers_flags(serde_json::json!({
            "environment_id": "local",
            "bundle_id": "my-bundle",
            "bundle_source_uri": "oci://registry.example/my-bundle@sha256:deadbeef",
            "remote_pins": {
                "bundle_digest": "sha256:deadbeef",
                "pack_list": [{
                    "pack_id": "p",
                    "version": "not-a-semver",
                    "digest": "sha256:aa",
                    "source_uri": "oci://registry.example/p@sha256:aa"
                }]
            }
        }));
        let err = remote_deploy(&build_dummy_store(), &flags, None).unwrap_err();
        assert!(
            matches!(err, OpError::InvalidArgument(ref m) if m.contains("pack version")),
            "got {err:?}"
        );
    }

    #[test]
    fn remote_deploy_keyed_stages_the_derived_revision() {
        // A keyed remote deploy stages the DETERMINISTIC revision id (so a
        // lost-response retry replays the same revision) under a `:stage` sub-key,
        // warms under `:warm`, and cuts over under the BARE deploy key (so a
        // completed retry is caught by the replay short-circuit). Capture every
        // request to assert the wiring.
        let key = "deploy-key-xyz";
        let derived = deploy_revision_id(Some(key)).to_string();
        let captured =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::<(String, String, String)>::new()));
        let cap = std::sync::Arc::clone(&captured);
        let check: CheckFn =
            std::sync::Arc::new(move |req_line: &str, headers: &str, body: &[u8]| {
                cap.lock().unwrap().push((
                    req_line.to_string(),
                    headers.to_lowercase(),
                    String::from_utf8_lossy(body).to_string(),
                ));
            });

        let get_body = serde_json::json!({
            "environment": env_json(), "etag": "sha256:test", "generation": 1
        })
        .to_string();
        let add_body = wrap_mutation(deploy_bundle_json());
        let stage_body = wrap_mutation(revision_json(&derived, "staged"));
        let warm_body = wrap_mutation(serde_json::json!({
            "revision": revision_json(&derived, "ready"),
            "environment": env_json(),
            "starting_lifecycle": "staged"
        }));
        let mut split = deploy_split_json();
        split["entries"] = serde_json::json!([{"revision_id": derived, "weight_bps": 10000}]);
        let traffic_body = wrap_mutation(serde_json::json!({
            "split": split, "previous_generation": null, "new_generation": 1,
            "environment": env_json()
        }));
        let mock = start_mock(
            vec![
                (200, &get_body),
                (201, &add_body),
                (201, &stage_body),
                (200, &warm_body),
                (200, &traffic_body),
            ],
            Some(check),
        );
        let store = mock_store(mock.addr, AuthMethod::None);
        let (_tmp, flags) = answers_flags(serde_json::json!({
            "environment_id": "local",
            "bundle_id": "my-bundle",
            "bundle_source_uri": "oci://registry.example/my-bundle@sha256:deadbeef",
            "idempotency_key": key,
            "remote_pins": {"bundle_digest": "sha256:deadbeef"}
        }));
        remote_deploy(&store, &flags, None).unwrap();

        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 5, "GET + add + stage + warm + traffic");
        let (stage_line, stage_headers, stage_body) = &reqs[2];
        assert!(
            stage_line.contains("/revisions"),
            "stage line: {stage_line}"
        );
        assert!(
            stage_body.contains(&derived),
            "stage must send the derived revision id {derived}: {stage_body}"
        );
        assert!(
            stage_headers.contains(&format!("idempotency-key: {key}:stage")),
            "stage headers: {stage_headers}"
        );
        assert!(
            reqs[3].1.contains(&format!("idempotency-key: {key}:warm")),
            "warm headers: {}",
            reqs[3].1
        );
        assert!(
            reqs[4].1.contains(&format!("idempotency-key: {key}")),
            "traffic must use the bare deploy key: {}",
            reqs[4].1
        );
    }

    #[test]
    fn env_list_dispatches_to_the_wire() {
        // `env list` reads the id set (GET /environments) then loads each env
        // (GET /environments/{id}) to build its summary — 1 + N GETs.
        let list_body = serde_json::json!({ "environments": ["local"] }).to_string();
        let get_body = serde_json::json!({
            "environment": env_json(),
            "etag": "sha256:test",
            "generation": 1
        })
        .to_string();
        let mock = start_mock(vec![(200, &list_body), (200, &get_body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let outcome = route_remote(
            &store,
            &no_flags(),
            OpNoun::Env {
                verb: EnvVerb::List,
            },
        )
        .unwrap();
        assert_eq!(outcome.noun, "env");
        assert_eq!(outcome.op, "list");
        let envs = outcome
            .result
            .get("environments")
            .and_then(|v| v.as_array())
            .expect("environments array");
        assert_eq!(envs.len(), 1);
    }

    #[test]
    fn trust_root_list_dispatches_to_the_wire() {
        // `trust-root list` reads the key set from GET /trust-root and renders
        // it through the shared `trust_root::list_outcome` projection.
        let body = serde_json::json!({ "environment_id": "local", "keys": [] }).to_string();
        let mock = start_mock(vec![(200, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let outcome = route_remote(
            &store,
            &no_flags(),
            OpNoun::TrustRoot {
                verb: TrustRootVerb::List {
                    env_id: "local".to_string(),
                },
            },
        )
        .unwrap();
        assert_eq!(outcome.noun, "trust-root");
        assert_eq!(outcome.op, "list");
        assert!(
            outcome
                .result
                .get("keys")
                .and_then(|v| v.as_array())
                .expect("keys array")
                .is_empty()
        );
    }

    #[test]
    fn messaging_rotate_webhook_secret_dispatches_to_the_wire() {
        // PR-4.2h removed the CLI-side guard: rotate now reaches the HTTP
        // store (the SERVER answers 501 until its secrets sink lands). With
        // a connection-refusing dummy store the verb must fail at the
        // transport — anything but the old CLI-side `NotYetImplemented`.
        let result = route_remote(
            &build_dummy_store(),
            &no_flags(),
            OpNoun::Messaging {
                verb: MessagingNoun::Endpoint {
                    verb: MessagingEndpointVerb::RotateWebhookSecret(
                        super::super::dispatch::MessagingEndpointRemoveArgs {
                            env: Some("local".to_string()),
                            endpoint_id: Some("01JABC000000000000000001ZZ".to_string()),
                            idempotency_key: None,
                            updated_by: Some("op".to_string()),
                        },
                    ),
                },
            },
        );
        assert!(result.is_err(), "dummy store must refuse the connection");
        assert!(
            !matches!(result, Err(OpError::NotYetImplemented(_))),
            "the CLI-side rotate guard must be gone"
        );
    }

    /// Build an `HttpEnvironmentStore` pointed at a port that will never accept.
    /// For tests that never reach the transport (blocked verbs).
    fn build_dummy_store() -> HttpEnvironmentStore {
        // Bind, then immediately drop to get a free port that refuses connections.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        HttpEnvironmentStore::new(
            url::Url::parse(&format!("http://{addr}")).unwrap(),
            AuthMethod::None,
        )
        .unwrap()
    }

    // -----------------------------------------------------------------------
    // env apply (remote): fail-closed validation, dry-run planning, execution
    // -----------------------------------------------------------------------

    fn env_json_for(id: &str) -> serde_json::Value {
        let mut v = env_json();
        v["environment_id"] = serde_json::json!(id);
        v["host_config"] = serde_json::json!({"env_id": id});
        v
    }

    fn manifest_from(json: serde_json::Value) -> EnvManifest {
        serde_json::from_value(json).expect("valid manifest json")
    }

    fn base_manifest_json(id: &str) -> serde_json::Value {
        serde_json::json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": id}
        })
    }

    #[test]
    fn reject_secrets_section() {
        let mut j = base_manifest_json("prod");
        j["secrets"] = serde_json::json!([{"path": "t/team/pack/api_key", "from_env": "API_KEY"}]);
        let err = reject_unsupported_remote_sections(&manifest_from(j)).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(m) if m.contains("secrets[]")));
    }

    #[test]
    fn reject_pack_binding_with_answers_ref() {
        let mut j = base_manifest_json("prod");
        j["packs"] = serde_json::json!([{
            "slot": "deployer",
            "kind": "greentic.deploy.deployer@1.0.0",
            "pack_ref": "local-deployer",
            "answers_ref": "deployer-answers.json"
        }]);
        let err = reject_unsupported_remote_sections(&manifest_from(j)).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(m) if m.contains("answers_ref")));
    }

    #[test]
    fn reject_extension_binding_with_answers_ref() {
        let mut j = base_manifest_json("prod");
        j["extensions"] = serde_json::json!([{
            "kind": "acme.oauth.auth0@1.0.0",
            "pack_ref": "auth0-pack",
            "answers_ref": "ext-answers.json"
        }]);
        let err = reject_unsupported_remote_sections(&manifest_from(j)).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(m) if m.contains("answers_ref")));
    }

    #[test]
    fn reject_telegram_class_endpoint() {
        let mut j = base_manifest_json("prod");
        j["messaging_endpoints"] = serde_json::json!([{
            "name": "support-bot",
            "provider_type": "messaging.telegram.bot"
        }]);
        let err = reject_unsupported_remote_sections(&manifest_from(j)).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(m) if m.contains("webhook_secret_ref")));
    }

    #[test]
    fn reject_bundle_without_source_uri() {
        let mut j = base_manifest_json("prod");
        j["bundles"] = serde_json::json!([{
            "bundle_id": "app",
            "bundle_path": "app.gtbundle",
            "customer_id": "acme"
        }]);
        let err = reject_unsupported_remote_sections(&manifest_from(j)).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(m) if m.contains("bundle_source_uri")));
    }

    #[test]
    fn reject_bundle_without_pinned_digest() {
        let mut j = base_manifest_json("prod");
        j["bundles"] = serde_json::json!([{
            "bundle_id": "app",
            "bundle_source_uri": "oci://registry.example/app:1",
            "customer_id": "acme"
        }]);
        let err = reject_unsupported_remote_sections(&manifest_from(j)).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(m) if m.contains("bundle_digest")));
    }

    #[test]
    fn reject_split_revision_without_pointers() {
        let mut j = base_manifest_json("prod");
        j["bundles"] = serde_json::json!([{
            "bundle_id": "app",
            "customer_id": "acme",
            "revisions": [
                {"name": "v1", "bundle_path": "v1.gtbundle", "weight_percent": 50,
                 "bundle_source_uri": "oci://r/app:1", "bundle_digest": "sha256:aa"},
                {"name": "v2", "bundle_path": "v2.gtbundle", "weight_percent": 50}
            ]
        }]);
        let err = reject_unsupported_remote_sections(&manifest_from(j)).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(m) if m.contains("revision `v2`")));
    }

    #[test]
    fn clean_manifest_passes_validation() {
        let mut j = base_manifest_json("prod");
        j["bundles"] = serde_json::json!([{
            "bundle_id": "app",
            "bundle_source_uri": "oci://registry.example/app:1",
            "bundle_digest": "sha256:abc123",
            "customer_id": "acme"
        }]);
        j["packs"] = serde_json::json!([{
            "slot": "deployer", "kind": "greentic.deploy.deployer@1.0.0", "pack_ref": "local"
        }]);
        assert!(reject_unsupported_remote_sections(&manifest_from(j)).is_ok());
    }

    #[test]
    fn remote_apply_dry_run_plans_without_mutating() {
        // Exactly ONE mock response (the load): a dry run must issue no
        // mutation calls (a second request would block on `accept` and hang).
        let load = serde_json::json!({"environment": env_json_for("prod")}).to_string();
        let mock = start_mock(vec![(200, &load)], None);
        let store = mock_store(mock.addr, AuthMethod::None);

        let manifest = serde_json::json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": "prod", "public_base_url": "https://prod.example"},
            "bundles": [{
                "bundle_id": "app",
                "bundle_source_uri": "oci://registry.example/app:1",
                "bundle_digest": "sha256:abc123",
                "customer_id": "acme"
            }],
            "messaging_endpoints": [{
                "name": "web", "provider_type": "messaging.webchat", "links": ["app"]
            }]
        });
        let (_tmp, flags) = answers_flags(manifest);
        let outcome = remote_env_apply(
            &store,
            &flags,
            ApplyOptions {
                mode: ApplyMode::DryRun,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(outcome.noun, "env");
        assert_eq!(outcome.op, "apply");
        assert_eq!(outcome.result["mode"], "dry-run");
        let steps = outcome.result["steps"].as_array().unwrap();
        assert!(steps.iter().any(|s| s["section"] == "environment"));
        assert!(
            steps
                .iter()
                .any(|s| s["section"] == "bundle" && s["action"] == "add")
        );
        assert!(steps.iter().any(|s| s["section"] == "revision"));
        assert!(steps.iter().any(|s| s["section"] == "traffic"));
        assert!(steps.iter().any(|s| s["section"] == "endpoint"));
        assert!(steps.iter().any(|s| s["section"] == "endpoint-link"));
    }

    #[test]
    fn remote_apply_reconciles_host_config() {
        // load → update_environment (host config declared). Env id `local`
        // matches `wrap_mutation`'s audit envelope, which the client correlates
        // against the targeted env.
        let load = serde_json::json!({"environment": env_json_for("local")}).to_string();
        let updated = wrap_mutation(env_json_for("local"));
        let mock = start_mock(vec![(200, &load), (200, &updated)], None);
        let store = mock_store(mock.addr, AuthMethod::None);

        let manifest = serde_json::json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": "local", "public_base_url": "https://prod.example", "name": "Prod"}
        });
        let (_tmp, flags) = answers_flags(manifest);
        let outcome = remote_env_apply(
            &store,
            &flags,
            ApplyOptions {
                mode: ApplyMode::Apply,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(outcome.result["mode"], "apply");
        assert!(
            outcome.result["steps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["section"] == "environment")
        );
    }

    #[test]
    fn remote_apply_requires_env_to_exist() {
        // load → 404: a named env must be created on the remote store first.
        let mock = start_mock(vec![(404, "{}")], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let manifest = serde_json::json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": "ghost"}
        });
        let (_tmp, flags) = answers_flags(manifest);
        let err = remote_env_apply(
            &store,
            &flags,
            ApplyOptions {
                mode: ApplyMode::Apply,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(matches!(err, OpError::NotFound(m) if m.contains("create it first")));
    }

    #[test]
    fn remote_apply_check_passes_when_converged() {
        // A manifest declaring only the env id (no host-config, bundles, or
        // endpoints) against an existing env is already converged: ONE load,
        // no mutations, exit 0. A second request would block `accept` and hang.
        let load = serde_json::json!({"environment": env_json_for("prod")}).to_string();
        let mock = start_mock(vec![(200, &load)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let manifest = serde_json::json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": "prod"}
        });
        let (_tmp, flags) = answers_flags(manifest);
        let outcome = remote_env_apply(
            &store,
            &flags,
            ApplyOptions {
                mode: ApplyMode::Check,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(outcome.result["mode"], "check");
        assert_eq!(outcome.result["pending_changes"], 0);
    }

    #[test]
    fn remote_apply_check_reports_drift_as_conflict() {
        // A manifest declaring a bundle the live env lacks is drift: check fails
        // (non-zero) without mutating — ONE load only.
        let load = serde_json::json!({"environment": env_json_for("prod")}).to_string();
        let mock = start_mock(vec![(200, &load)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let manifest = serde_json::json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": "prod"},
            "bundles": [{
                "bundle_id": "app",
                "bundle_source_uri": "oci://registry.example/app:1",
                "bundle_digest": "sha256:abc123",
                "customer_id": "acme"
            }]
        });
        let (_tmp, flags) = answers_flags(manifest);
        let err = remote_env_apply(
            &store,
            &flags,
            ApplyOptions {
                mode: ApplyMode::Check,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(m) if m.contains("not converged")));
    }

    #[test]
    fn remote_apply_check_host_config_match_is_noop() {
        // Declaring a host-config field that already equals the live value is NOT
        // drift — the env step reconciles only on a real difference, so check
        // passes (the pre-diff code emitted an unconditional reconcile here).
        let load = serde_json::json!({"environment": env_json_for("prod")}).to_string();
        let mock = start_mock(vec![(200, &load)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        // env_json_for(..) carries name "test"; declaring the same is a no-op.
        let manifest = serde_json::json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": "prod", "name": "test"}
        });
        let (_tmp, flags) = answers_flags(manifest);
        let outcome = remote_env_apply(
            &store,
            &flags,
            ApplyOptions {
                mode: ApplyMode::Check,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(outcome.result["pending_changes"], 0);
        assert!(
            outcome.result["steps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["section"] == "environment" && s["action"] == "current")
        );
    }

    // -- host-config diff (pure) ---------------------------------------------

    fn manifest_env(json: serde_json::Value) -> super::super::env_manifest::ManifestEnvironment {
        manifest_from(serde_json::json!({
            "schema": "greentic.env-manifest.v1",
            "environment": json
        }))
        .environment
    }

    #[test]
    fn host_config_no_drift_when_declared_matches_live() {
        let env = env_of(env_json_for("prod")); // name "test", no public_base_url
        let (_payload, differs) = resolve_host_config_update(
            &manifest_env(serde_json::json!({"id": "prod", "name": "test"})),
            &env,
        )
        .unwrap();
        assert!(!differs);
    }

    #[test]
    fn host_config_drift_on_changed_field() {
        let env = env_of(env_json_for("prod"));
        // name differs from live "test".
        let (_p, differs) = resolve_host_config_update(
            &manifest_env(serde_json::json!({"id": "prod", "name": "Prod"})),
            &env,
        )
        .unwrap();
        assert!(differs);
        // public_base_url declared where live has none.
        let (_p, differs) = resolve_host_config_update(
            &manifest_env(
                serde_json::json!({"id": "prod", "public_base_url": "https://prod.example"}),
            ),
            &env,
        )
        .unwrap();
        assert!(differs);
    }

    // -- binding + trust-root drift in --check (codex hardening) -------------

    #[test]
    fn remote_apply_check_passes_when_trust_root_seeded() {
        // load → trust-root GET (keys present). A seeded root is converged.
        let load = serde_json::json!({"environment": env_json_for("prod")}).to_string();
        let tr =
            serde_json::json!({"environment_id": "prod", "keys": [{"key_id": "k"}]}).to_string();
        let mock = start_mock(vec![(200, &load), (200, &tr)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let manifest = serde_json::json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": "prod"},
            "trust_root": "bootstrap"
        });
        let (_tmp, flags) = answers_flags(manifest);
        let outcome = remote_env_apply(
            &store,
            &flags,
            ApplyOptions {
                mode: ApplyMode::Check,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(outcome.result["pending_changes"], 0);
    }

    #[test]
    fn remote_apply_check_reports_unseeded_trust_root_as_drift() {
        // load → trust-root GET (no keys). An unseeded root is drift, not a
        // silent green (the bug the read probe fixes).
        let load = serde_json::json!({"environment": env_json_for("prod")}).to_string();
        let tr = serde_json::json!({"environment_id": "prod", "keys": []}).to_string();
        let mock = start_mock(vec![(200, &load), (200, &tr)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let manifest = serde_json::json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": "prod"},
            "trust_root": "bootstrap"
        });
        let (_tmp, flags) = answers_flags(manifest);
        let err = remote_env_apply(
            &store,
            &flags,
            ApplyOptions {
                mode: ApplyMode::Check,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(m) if m.contains("not converged")));
    }

    #[test]
    fn remote_apply_check_reports_pack_ref_drift() {
        // Slot bound to a different pack_ref → drift (update), not skip-bound.
        let mut env = env_json_for("prod");
        env["packs"] = serde_json::json!([{
            "slot": "deployer", "kind": "greentic.deploy.deployer@1.0.0", "pack_ref": "oldref"
        }]);
        let load = serde_json::json!({"environment": env}).to_string();
        let mock = start_mock(vec![(200, &load)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let manifest = serde_json::json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": "prod"},
            "packs": [{
                "slot": "deployer", "kind": "greentic.deploy.deployer@1.0.0", "pack_ref": "newref"
            }]
        });
        let (_tmp, flags) = answers_flags(manifest);
        let err = remote_env_apply(
            &store,
            &flags,
            ApplyOptions {
                mode: ApplyMode::Check,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(m) if m.contains("not converged")));
    }

    #[test]
    fn remote_apply_check_reports_extension_ref_drift() {
        // Same (path, instance) bound to a different pack_ref → drift (update).
        let mut env = env_json_for("prod");
        env["extensions"] = serde_json::json!([{
            "kind": "greentic.ext.memory@1.0.0", "pack_ref": "oldref", "instance_id": "default"
        }]);
        let load = serde_json::json!({"environment": env}).to_string();
        let mock = start_mock(vec![(200, &load)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let manifest = serde_json::json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": "prod"},
            "extensions": [{
                "kind": "greentic.ext.memory@1.0.0", "pack_ref": "newref", "instance_id": "default"
            }]
        });
        let (_tmp, flags) = answers_flags(manifest);
        let err = remote_env_apply(
            &store,
            &flags,
            ApplyOptions {
                mode: ApplyMode::Check,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(m) if m.contains("not converged")));
    }

    // -- convergence + metadata-diff (the durable-reconcile core) -------------

    const TEST_DEPLOYMENT_ID: &str = "01JABC000000000000000000ZZ";

    fn converged_env_json(digest: &str, source_uri: &str, weight_bps: u32) -> serde_json::Value {
        serde_json::json!({
            "schema": "greentic.environment.v1",
            "environment_id": "prod",
            "name": "prod",
            "host_config": {"env_id": "prod"},
            "packs": [],
            "bundles": [deployment_json(&[])],
            "revisions": [{
                "schema": "greentic.revision.v1",
                "revision_id": TEST_REV_ID,
                "env_id": "prod",
                "bundle_id": "app",
                "deployment_id": TEST_DEPLOYMENT_ID,
                "sequence": 1,
                "created_at": "2026-06-09T12:00:00Z",
                "bundle_digest": digest,
                "bundle_source_uri": source_uri,
                "pack_list": [],
                "pack_list_lock_ref": "",
                "pack_config_refs": [],
                "config_digest": "sha256:00",
                "signature_sidecar_ref": "rev.sig",
                "lifecycle": "ready",
                "staged_at": "2026-06-09T12:00:00Z",
                "drain_seconds": 30,
                "abort_metrics": []
            }],
            "traffic_splits": [{
                "schema": "greentic.traffic-split.v1",
                "env_id": "prod",
                "deployment_id": TEST_DEPLOYMENT_ID,
                "bundle_id": "app",
                "generation": 1,
                "entries": [{"revision_id": TEST_REV_ID, "weight_bps": weight_bps}],
                "updated_at": "2026-06-09T12:00:00Z",
                "updated_by": "x",
                "idempotency_key": "k",
                "authorization_ref": "auth.json"
            }],
            "messaging_endpoints": [],
            "extensions": [],
            "revocation": {},
            "retention": {},
            "health": {}
        })
    }

    fn deployment_json(route_hosts: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "schema": "greentic.bundle-deployment.v1",
            "deployment_id": TEST_DEPLOYMENT_ID,
            "env_id": "prod",
            "bundle_id": "app",
            "customer_id": "acme",
            "status": "active",
            "current_revisions": [],
            "route_binding": {"hosts": route_hosts, "path_prefixes": [],
                "tenant_selector": {"tenant": "default", "team": "default"}},
            "revenue_share": [{"party_id": "greentic", "basis_points": 10000}],
            "revenue_policy_ref": "revenue.json",
            "created_at": "2026-06-09T12:00:00Z",
            "authorization_ref": "auth.json",
            "config_overrides": {}
        })
    }

    fn env_of(json: serde_json::Value) -> greentic_deploy_spec::Environment {
        serde_json::from_value(json).expect("valid environment json")
    }

    fn dep_id() -> greentic_deploy_spec::DeploymentId {
        parse_deployment_id(TEST_DEPLOYMENT_ID).unwrap()
    }

    fn desired(weight_bps: u32, source_uri: &str, digest: &str) -> DesiredRevision {
        DesiredRevision {
            name: "r".to_string(),
            weight_bps,
            source_uri: source_uri.to_string(),
            digest: digest.to_string(),
            drain_seconds: 30,
        }
    }

    #[test]
    fn convergence_true_when_split_matches_desired() {
        let env = env_of(converged_env_json("sha256:abc123", "oci://r/app:1", 10000));
        assert!(deployment_converged_remote(
            &env,
            dep_id(),
            &[desired(10000, "oci://r/app:1", "sha256:abc123")]
        ));
    }

    #[test]
    fn convergence_false_on_digest_or_source_uri_drift() {
        let env = env_of(converged_env_json("sha256:abc123", "oci://r/app:1", 10000));
        // Changed digest → a new revision is owed.
        assert!(!deployment_converged_remote(
            &env,
            dep_id(),
            &[desired(10000, "oci://r/app:1", "sha256:def456")]
        ));
        // Changed pull ref (same digest) → still not converged.
        assert!(!deployment_converged_remote(
            &env,
            dep_id(),
            &[desired(10000, "oci://r/app:2", "sha256:abc123")]
        ));
    }

    #[test]
    fn convergence_false_on_placeholder_digest() {
        // A live revision carrying the local-serve placeholder digest is never
        // "converged" — a remote worker cannot verify it.
        let env = env_of(converged_env_json("sha256:00", "oci://r/app:1", 10000));
        assert!(!deployment_converged_remote(
            &env,
            dep_id(),
            &[desired(10000, "oci://r/app:1", "sha256:00")]
        ));
    }

    #[test]
    fn metadata_update_none_when_nothing_declared() {
        let b: ManifestBundle = serde_json::from_value(serde_json::json!({
            "bundle_id": "app", "customer_id": "acme",
            "bundle_source_uri": "oci://r/app:1", "bundle_digest": "sha256:abc123"
        }))
        .unwrap();
        let dep: greentic_deploy_spec::BundleDeployment =
            serde_json::from_value(deployment_json(&[])).unwrap();
        assert!(bundle_metadata_update(&b, &dep).is_none());
    }

    #[test]
    fn metadata_update_some_on_route_drift() {
        let b: ManifestBundle = serde_json::from_value(serde_json::json!({
            "bundle_id": "app", "customer_id": "acme",
            "bundle_source_uri": "oci://r/app:1", "bundle_digest": "sha256:abc123",
            "route_binding": {"hosts": ["app.example.com"], "path_prefixes": []}
        }))
        .unwrap();
        let dep: greentic_deploy_spec::BundleDeployment =
            serde_json::from_value(deployment_json(&[])).unwrap();
        let update = bundle_metadata_update(&b, &dep).expect("route drift produces an update");
        assert!(update.route_binding.is_some());
        assert!(update.status.is_none());
        assert!(update.revenue_share.is_none());
    }

    // -- remote env reconcile -----------------------------------------------
    // The convergence itself needs a live cluster (`reconcile_k8s_cluster`), so
    // — exactly like the local `reconcile` tests — these cover the gate/validation
    // surface and stop before any cluster contact.

    /// Wrap a typed env in the `GET /environments/{id}` response shape
    /// (`load_environment` reads `{ environment, etag }`).
    fn get_env_response(env: &greentic_deploy_spec::Environment) -> String {
        serde_json::json!({ "environment": env, "etag": "sha256:test" }).to_string()
    }

    fn reconcile_args(env_id: &str) -> crate::cli::dispatch::EnvReconcileArgs {
        crate::cli::dispatch::EnvReconcileArgs {
            env_id: env_id.to_string(),
            kind: None,
        }
    }

    /// A k8s-deployer + Vault-secrets env — the only binding shape remote
    /// reconcile accepts (all gates pass; the reconcile then needs a cluster).
    fn k8s_vault_env() -> greentic_deploy_spec::Environment {
        use crate::cli::tests_common::{make_binding, make_env};
        use greentic_deploy_spec::CapabilitySlot;
        let mut env = make_env("prod");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.k8s@1.0.0",
        ));
        env.packs.push(make_binding(
            CapabilitySlot::Secrets,
            crate::defaults::VAULT_SECRETS_PACK,
        ));
        env
    }

    #[test]
    fn remote_reconcile_env_not_found_is_mapped() {
        let mock = start_mock(vec![(404, "{\"error\":\"nope\"}")], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let err = remote_reconcile(&store, &no_flags(), reconcile_args("ghost")).unwrap_err();
        assert!(matches!(err, OpError::NotFound(_)), "got {err:?}");
    }

    #[test]
    fn remote_reconcile_rejects_no_deployer_binding() {
        use crate::cli::tests_common::make_env;
        let env = make_env("prod"); // packs empty → no deployer binding
        let mock = start_mock(vec![(200, &get_env_response(&env))], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let err = remote_reconcile(&store, &no_flags(), reconcile_args("prod")).unwrap_err();
        assert!(
            matches!(err, OpError::Conflict(ref m) if m.contains("deployer binding")),
            "got {err:?}"
        );
    }

    #[test]
    fn remote_reconcile_rejects_non_k8s_deployer() {
        use crate::cli::tests_common::{make_binding, make_env};
        use greentic_deploy_spec::CapabilitySlot;
        let mut env = make_env("prod");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            crate::defaults::LOCAL_DEPLOYER_PACK,
        ));
        let mock = start_mock(vec![(200, &get_env_response(&env))], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let err = remote_reconcile(&store, &no_flags(), reconcile_args("prod")).unwrap_err();
        assert!(
            matches!(err, OpError::Conflict(ref m) if m.contains("only supported for")),
            "got {err:?}"
        );
    }

    #[test]
    fn remote_reconcile_rejects_dev_store_secrets() {
        use crate::cli::tests_common::{make_binding, make_env};
        use greentic_deploy_spec::CapabilitySlot;
        let mut env = make_env("prod");
        env.packs.push(make_binding(
            CapabilitySlot::Deployer,
            "greentic.deployer.k8s@1.0.0",
        ));
        env.packs.push(make_binding(
            CapabilitySlot::Secrets,
            crate::defaults::LOCAL_SECRETS_PACK, // dev-store backend
        ));
        let mock = start_mock(vec![(200, &get_env_response(&env))], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let err = remote_reconcile(&store, &no_flags(), reconcile_args("prod")).unwrap_err();
        assert!(
            matches!(err, OpError::Conflict(ref m) if m.contains("Vault secrets backend")),
            "got {err:?}"
        );
    }

    #[test]
    fn remote_reconcile_requires_answers() {
        // A k8s + Vault env clears every binding gate, but reconcile needs the
        // operator's local answers — the control-plane store keeps none.
        let env = k8s_vault_env();
        let mock = start_mock(vec![(200, &get_env_response(&env))], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let err = remote_reconcile(&store, &no_flags(), reconcile_args("prod")).unwrap_err();
        assert!(
            matches!(err, OpError::InvalidArgument(ref m) if m.contains("--answers")),
            "got {err:?}"
        );
    }

    #[test]
    fn remote_reconcile_requires_vault_addr_role() {
        // `--answers` present but the Vault block omits addr/role → fail closed
        // (the same pure mapping the local path uses) before any cluster contact.
        let env = k8s_vault_env();
        let mock = start_mock(vec![(200, &get_env_response(&env))], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let (_tmp, flags) = answers_flags(serde_json::json!({})); // no secrets_answers
        let err = remote_reconcile(&store, &flags, reconcile_args("prod")).unwrap_err();
        assert!(
            matches!(err, OpError::Conflict(ref m) if m.contains("addr")),
            "got {err:?}"
        );
    }

    /// Once the gates pass, reconcile routes through the server-mediated
    /// `env.reconcile` op: the GET-cached ETag MUST replay as `If-Match` on the
    /// POST (CAS), and a 412 — the env advanced under us — surfaces as a
    /// Conflict carrying the re-run guidance, never a silent stale apply.
    #[test]
    fn remote_reconcile_pins_if_match_and_maps_concurrent_advance() {
        let env = k8s_vault_env();
        let requests: Arc<std::sync::Mutex<Vec<(String, String)>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = requests.clone();
        let check: CheckFn = Arc::new(move |req_line: &str, headers: &str, _body: &[u8]| {
            recorder
                .lock()
                .unwrap()
                .push((req_line.to_string(), headers.to_lowercase()));
        });
        let mock = start_mock(
            vec![
                (200, &get_env_response(&env)), // load_environment read
                (412, r#"{"detail":"stale"}"#), // reconcile POST: env advanced
            ],
            Some(check),
        );
        let store = mock_store(mock.addr, AuthMethod::None);
        let (_tmp, flags) = answers_flags(serde_json::json!({
            "secrets_answers": {"addr": "http://vault.local:8200", "role": "greentic-worker"}
        }));
        let err = remote_reconcile(&store, &flags, reconcile_args("prod")).unwrap_err();

        assert!(
            matches!(err, OpError::Conflict(ref m) if m.contains("re-run")),
            "412 must surface as a re-run Conflict, got {err:?}"
        );
        let reqs = requests.lock().unwrap();
        assert_eq!(
            reqs.len(),
            2,
            "expected GET then reconcile POST, got {reqs:?}"
        );
        assert!(
            reqs[0].0.starts_with("GET "),
            "first request is the read: {}",
            reqs[0].0
        );
        assert!(
            reqs[1].0.starts_with("POST ") && reqs[1].0.contains("/reconcile"),
            "second request is the reconcile POST: {}",
            reqs[1].0
        );
        assert!(
            reqs[1].1.contains("if-match: \"sha256:test\""),
            "reconcile POST must replay the reviewed ETag as If-Match: {}",
            reqs[1].1
        );
        assert!(
            reqs[1].1.contains("idempotency-key:"),
            "reconcile POST must carry an idempotency key: {}",
            reqs[1].1
        );
    }

    /// The whole point of routing reconcile through the store: a denial
    /// (e.g. a read-only token) is refused server-side and surfaces with the
    /// typed `unauthorized` noun — not as a silent local apply that bypassed
    /// the control plane's authorization boundary.
    #[test]
    fn remote_reconcile_surfaces_server_authz_denial() {
        let env = k8s_vault_env();
        let mock = start_mock(
            vec![
                (200, &get_env_response(&env)),
                (
                    403,
                    r#"{"kind":"unauthorized","policy":"rbac-v1","reason":"read-only token"}"#,
                ),
            ],
            None,
        );
        let store = mock_store(mock.addr, AuthMethod::None);
        let (_tmp, flags) = answers_flags(serde_json::json!({
            "secrets_answers": {"addr": "http://vault.local:8200", "role": "greentic-worker"}
        }));
        let err = remote_reconcile(&store, &flags, reconcile_args("prod")).unwrap_err();
        assert!(
            matches!(err, OpError::Unauthorized { ref reason, .. } if reason.contains("read-only")),
            "server authz denial must surface as Unauthorized, got {err:?}"
        );
    }
}
