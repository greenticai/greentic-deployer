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

use greentic_deploy_spec::{
    BundleId, DeploymentId, EnvId, EnvironmentHostConfig, IdempotencyKey, MessagingEndpointId,
    PackId, RevenueShareEntry, RevisionId,
};
use serde_json::json;

use crate::environment::{
    AddBundlePayload, AddMessagingEndpointPayload, AuthMethod, EnvironmentMutations, FieldUpdate,
    HttpEnvironmentStore, RemoveBundleOutcome, SetMessagingWelcomeFlowPayload, UpdateBundlePayload,
    UpdateEnvironmentPayload,
};

use super::dispatch::{
    BundlesVerb, ConfigVerb, CredentialsVerb, EnvPacksVerb, EnvVerb, ExtensionsVerb,
    MessagingEndpointVerb, MessagingNoun, OpCommand, OpNoun, RevisionsVerb, SecretsVerb,
    TrafficVerb, TrustRootVerb, print_outcome,
};
use super::{OpError, OpFlags, OpOutcome, map_store_err_preserving_noun};

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

fn route_remote(
    store: &dyn EnvironmentMutations,
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
            EnvVerb::List => Err(not_supported("env list")),
            EnvVerb::Show { .. } => Err(not_supported("env show")),
            EnvVerb::Doctor { .. } => Err(not_supported("env doctor")),
            EnvVerb::ToolCheck { .. } => Err(not_supported("env tool-check")),
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
            EnvPacksVerb::List { .. } => Err(not_supported("env-packs list")),
        },

        // -- extensions --------------------------------------------------------
        OpNoun::Extensions { verb } => match verb {
            ExtensionsVerb::Add => remote_extensions_add(store, flags),
            ExtensionsVerb::Update => remote_extensions_update(store, flags),
            ExtensionsVerb::Remove => remote_extensions_remove(store, flags),
            ExtensionsVerb::Rollback => remote_extensions_rollback(store, flags),
            ExtensionsVerb::List { .. } => Err(not_supported("extensions list")),
        },

        // -- bundles -----------------------------------------------------------
        OpNoun::Bundles { verb } => match verb {
            BundlesVerb::Add => remote_bundles_add(store, flags),
            BundlesVerb::Update => remote_bundles_update(store, flags),
            BundlesVerb::Remove => remote_bundles_remove(store, flags),
            BundlesVerb::List { .. } => Err(not_supported("bundles list")),
        },

        // -- traffic -----------------------------------------------------------
        OpNoun::Traffic { verb } => match verb {
            TrafficVerb::Set(args) => {
                let payload = super::traffic::payload_from_set_args(args)?;
                remote_traffic_set(store, flags, payload)
            }
            TrafficVerb::Show(_) => Err(not_supported("traffic show")),
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
            RevisionsVerb::Stage(_) => Err(OpError::NotYetImplemented(
                "`revisions stage` against a remote --store-url store is not supported yet \
                 (needs server-side bundle staging / a GET-env read endpoint; \
                 tracked as PR-3c follow-up)"
                    .to_string(),
            )),
            RevisionsVerb::Warm => Err(OpError::NotYetImplemented(
                "`revisions warm` against a remote --store-url store is not supported yet \
                 (needs a GET-env read endpoint for the health-gate precondition; \
                 tracked as PR-3c follow-up)"
                    .to_string(),
            )),
            RevisionsVerb::List { .. } => Err(not_supported("revisions list")),
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
                MessagingEndpointVerb::RotateWebhookSecret(_) => Err(OpError::NotYetImplemented(
                    "`messaging rotate-webhook-secret` against a remote --store-url store \
                         is not supported yet (writes the secret to the local dev-store; needs \
                         server-side secret handling; tracked as PR-3c follow-up)"
                        .to_string(),
                )),
                MessagingEndpointVerb::List { .. } => Err(not_supported("messaging.endpoint list")),
                MessagingEndpointVerb::Show { .. } => Err(not_supported("messaging.endpoint show")),
            },
        },

        // -- trust-root --------------------------------------------------------
        OpNoun::TrustRoot { verb } => match verb {
            TrustRootVerb::Bootstrap { env_id } => {
                remote_trust_root_bootstrap(store, flags, env_id)
            }
            TrustRootVerb::Add(args) => remote_trust_root_add(store, flags, args),
            TrustRootVerb::Remove(args) => remote_trust_root_remove(store, flags, args),
            TrustRootVerb::List { .. } => Err(not_supported("trust-root list")),
        },

        // -- local-only nouns --------------------------------------------------
        OpNoun::Deploy(_) => Err(not_supported("deploy")),
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
                idempotency_key,
            },
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
                idempotency_key,
            },
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
            deployment_id,
            parsed_entries,
            idempotency_key,
            payload.updated_by,
            Some(payload.authorization_ref.to_string_lossy().into_owned()),
        )
        .map_err(super::traffic::map_traffic_store_err)?;
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
    let idempotency_key = super::resolve_idempotency_key(payload.idempotency_key)?;
    let ep = store
        .add_messaging_endpoint(
            &env_id,
            AddMessagingEndpointPayload {
                provider_id,
                provider_type,
                display_name,
                secret_refs: payload.secret_refs,
                updated_by,
                idempotency_key,
            },
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
                idempotency_key,
            },
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
            "new_generation": 1
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
                idempotency_key: None,
                updated_by: "operator".to_string(),
            }),
        )
        .unwrap();
        assert_eq!(outcome.noun, "messaging.endpoint");
        assert_eq!(outcome.op, "add");
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

    #[test]
    fn revisions_stage_blocked() {
        let result = route_remote(
            // Pass a dummy store — the verb must reject before calling it.
            // We use a mock server that will never be contacted.
            &build_dummy_store(),
            &no_flags(),
            OpNoun::Revisions {
                verb: RevisionsVerb::Stage(super::super::dispatch::RevisionStageArgs {
                    env_id: Some("local".to_string()),
                    deployment: None,
                    bundle: None,
                }),
            },
        );
        assert!(
            matches!(result, Err(OpError::NotYetImplemented(m)) if m.contains("revisions stage"))
        );
    }

    #[test]
    fn revisions_warm_blocked() {
        let result = route_remote(
            &build_dummy_store(),
            &no_flags(),
            OpNoun::Revisions {
                verb: RevisionsVerb::Warm,
            },
        );
        assert!(
            matches!(result, Err(OpError::NotYetImplemented(m)) if m.contains("revisions warm"))
        );
    }

    #[test]
    fn messaging_rotate_webhook_secret_blocked() {
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
        assert!(
            matches!(result, Err(OpError::NotYetImplemented(m)) if m.contains("rotate-webhook-secret"))
        );
    }

    #[test]
    fn env_list_is_local_only() {
        let result = route_remote(
            &build_dummy_store(),
            &no_flags(),
            OpNoun::Env {
                verb: EnvVerb::List,
            },
        );
        assert!(matches!(result, Err(OpError::NotYetImplemented(_))));
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
}
