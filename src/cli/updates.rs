//! `gtc op updates {enroll,status}` — P1b update-channel client-certificate
//! enrollment (Phase 1 of the Greentic updater).
//!
//! `enroll` mints a fresh key pair + CSR (via `greentic-update`), exchanges it
//! at the Cert-CA's `/v1/enroll` endpoint for a signed client certificate, and
//! persists the cert + key + issuing CA (and the CA URL) into the env's
//! configured secrets backend under the `tls` pack. Running it again overwrites
//! the stored material — so it is also the manual rotation path. `status` reads
//! the stored certificate back and reports its serial + validity window.
//!
//! Enrollment happens *before* the client holds a certificate, so it cannot use
//! the mTLS update channel itself: this verb drives `greentic-update::enroll`
//! over a plain server-auth bootstrap client. Persistence lives here (the
//! caller), not in `greentic-update`, which stays free of any secrets
//! dependency — the crate returns raw PEM and the operator persists it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use greentic_deploy_spec::{
    DEFAULT_PLAN_ENDPOINT, EnvId, Environment, MIN_POLL_INTERVAL_SECS, UpdateAction,
    UpdateChannelConfig,
};
use greentic_distributor_client::{CachePolicy, DistClient, DistOptions, ResolvePolicy};
use greentic_secrets_lib::core::rt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::{
    EnvironmentStore, LocalFsStore, restore_environment, snapshot_environment,
    trust_root as store_trust_root,
};

use super::env_manifest::{ENV_MANIFEST_SCHEMA_V1, EnvManifest};
use super::secrets::{get_env_secret, put_env_secret, require_secrets_pack};
use super::{AuditCtx, OpError, OpFlags, OpOutcome, audit_and_record};

const NOUN: &str = "updates";

/// Secrets pack (category) the update-channel TLS material lives under.
const TLS_PACK: &str = "tls";
/// Store-canonical secret name for the enrolled mTLS identity (single underscore
/// — the runtime reader collapses `__` to `_`, so a double-underscore name would
/// never be found). The whole identity is persisted under this ONE name as a
/// JSON [`StoredIdentity`] blob rather than as four separate
/// `updater_cert`/`updater_key`/`updater_ca`/`updater_ca_url` secrets: a single
/// write is atomic at the granularity the dev-store / Vault backends offer, so a
/// re-enrollment (rotation) can never leave a fresh private key paired with the
/// PREVIOUS certificate — a mismatch `status` would still report as enrolled
/// while every mTLS handshake fails.
const IDENTITY_NAME: &str = "updater_identity";

/// The enrolled update-channel mTLS identity, persisted as one JSON secret under
/// [`IDENTITY_NAME`]. Written atomically by `enroll`; read by `status` and the
/// plan fetch.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredIdentity {
    client_key_pem: String,
    client_cert_pem: String,
    ca_pem: String,
    /// The Cert-CA base URL enrollment used. Retained for audit and the Phase 6
    /// poll; not read on the fetch path today.
    ca_url: String,
}

/// Payload for `op updates enroll`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatesEnrollPayload {
    pub environment_id: String,
    /// Base URL of the Cert-CA (`greentic-updates-server`). The `/v1/enroll`
    /// path is appended.
    pub ca_url: String,
}

/// Payload for `op updates status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatesStatusPayload {
    pub environment_id: String,
}

/// Payload for `op updates get`. Exactly one plan source is required: `plan_url`
/// (fetched over the enrolled mTLS channel) or the `plan_file` + `plan_sig_file`
/// pair (airgap import / local testing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatesGetPayload {
    pub environment_id: String,
    /// Fetch the signed plan document + `.sig` sidecar from this base URL over
    /// the enrolled mTLS channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_url: Option<String>,
    /// Local plan document (airgap import / testing). Requires `plan_sig_file`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_file: Option<PathBuf>,
    /// DSSE envelope sidecar for `plan_file`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_sig_file: Option<PathBuf>,
}

/// Payload for `op updates apply` — apply a staged plan to its environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyUpdatesPayload {
    pub environment_id: String,
    /// Plan id of the staged plan to apply (from a prior `op updates get`).
    pub plan_id: String,
}

/// Payload for `op updates recover` — force a plan stranded in `applying` by a
/// crashed applier to `failed`, so a fresh `get` + `apply` can proceed. The
/// `--force` attestation is a CLI-only argument (operator intent, not a
/// replayable answers field), so it is threaded separately, not carried here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverUpdatesPayload {
    pub environment_id: String,
    /// Plan id of the `applying` plan to force-fail (from a prior `op updates get`).
    pub plan_id: String,
}

/// Payload for `op updates config-set` — set the update-channel notification
/// policy (`update-channel.json`). Every behavior field is optional; only those
/// supplied are changed, the rest keep their stored value (same semantics as
/// `op config set`). Enrollment/identity is unaffected — this is policy only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfigSetPayload {
    pub environment_id: String,
    /// Master switch for the notification machinery. `None` leaves the stored
    /// value unchanged; absent file resolves to disabled (deny-by-default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Action on a verified plan: `record-only`, `stage`, or `apply`. `None`
    /// leaves the stored value unchanged (unset resolves to `stage`). Writes
    /// both `on_update` and the legacy `on_notify` mirror.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_notify: Option<String>,
    /// Fallback poll interval in seconds (rejected below the 60s floor). `None`
    /// leaves the stored value unchanged (unset resolves to 3600).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poll_interval_secs: Option<u64>,
    /// Base URL to poll for the latest signed update plan (`{url}` + `{url}.sig`).
    /// `None` leaves the stored value unchanged; must be https (or http to
    /// loopback).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_endpoint: Option<String>,
    /// Whether the runtime subscribes to a pushed update stream (SSE). `None`
    /// leaves the stored value unchanged (unset resolves to `true`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_enabled: Option<bool>,
    /// SSE stream endpoint URL. `None` leaves the stored value unchanged; must
    /// be https (or http to loopback). When unset, the runtime derives from
    /// `plan_endpoint`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_endpoint: Option<String>,
}

/// Filter for `op updates config-show` — read-only view of the update-channel
/// policy (stored fields + resolved effective values).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfigShowFilter {
    pub environment_id: String,
}

/// The dev-store/Vault secret path for one TLS artifact: `<tenant>/_/tls/<name>`
/// (`<tenant>/<team>/<pack>/<name>` with the default team `_`).
fn tls_rel_path(tenant: &str, name: &str) -> String {
    format!("{tenant}/_/{TLS_PACK}/{name}")
}

/// Whether a control-plane URL (the Cert-CA for enrollment, or the plan-fetch
/// endpoint for `get`) is acceptable. HTTPS is always allowed. Plaintext
/// `http://` is allowed ONLY to a loopback host, for local development: over
/// plaintext the enrolled mTLS client identity is never presented and a remote
/// on-path attacker could serve a malicious CA (enrollment) or a stale
/// validly-signed plan (fetch). A hostname that merely starts with `127.` (e.g.
/// `127.0.0.1.evil.com`) parses as a domain, not a loopback IP, so it is refused.
pub(crate) fn control_url_is_acceptable(raw: &str) -> bool {
    let Ok(parsed) = url::Url::parse(raw) else {
        return false;
    };
    match parsed.scheme() {
        "https" => true,
        "http" => match parsed.host() {
            Some(url::Host::Domain(host)) => host == "localhost",
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        },
        _ => false,
    }
}

/// The enrolled certificate's identity is the env's owning tenant, so an owner
/// is required. Mirrors `vault_seed_put`'s fail-closed tenant guard (a
/// Vault-backed env is single-tenant at the runtime) so the two write surfaces
/// agree on the tenant segment.
fn require_tenant(env: &Environment, env_id: &EnvId) -> Result<String, OpError> {
    env.host_config
        .tenant_org_id
        .clone()
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| {
            OpError::InvalidArgument(format!(
                "env `{env_id}` must be tenant-owned before update-channel enrollment; \
                 set the owner with `op env update {env_id} --tenant-org <tenant>`"
            ))
        })
}

/// `op updates enroll` — enroll with the Cert-CA and persist the signed client
/// certificate + key + issuing CA (and the CA URL) into the env secrets backend.
/// Idempotent by overwrite: re-running mints a fresh identity (manual rotation).
pub fn enroll(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<UpdatesEnrollPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "enroll", enroll_schema()));
    }
    let payload = resolve_payload::<UpdatesEnrollPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    // Validate the CA URL before the authz gate / any network work.
    let ca_url = payload.ca_url.trim().to_string();
    if ca_url.is_empty() {
        return Err(OpError::InvalidArgument(
            "ca_url must not be empty".to_string(),
        ));
    }
    if !control_url_is_acceptable(&ca_url) {
        return Err(OpError::InvalidArgument(
            "ca_url must be an https:// URL; plaintext http:// is accepted only for a loopback \
             CA in local development. Enrollment establishes the update-channel trust anchor, so \
             it must not bootstrap over an unauthenticated channel to a remote host."
                .to_string(),
        ));
    }
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "enroll",
        // Audit target carries the CA URL and env, never key material.
        target: json!({"environment_id": env_id.as_str(), "ca_url": ca_url}),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        let env = store.load(&env_id)?;
        let secrets = require_secrets_pack(&env, &env_id)?;
        let kind_path = secrets.kind.path();
        let tenant = require_tenant(&env, &env_id)?;

        // Enrollment predates the client cert, so drive it over a plain
        // server-auth client (not the mTLS one). Bridge the async call from
        // this synchronous verb, mirroring `vault_seed_put`.
        let enrollment = rt::sync_await(async {
            let client = reqwest::Client::new();
            greentic_update::enroll::enroll(&client, &ca_url, &tenant, env_id.as_str()).await
        })
        .map_err(|e| OpError::Conflict(format!("update-channel enrollment failed: {e}")))?;

        // Validate the CA response before persisting: prove the ca/cert/key
        // parse and load as an mTLS identity, so structurally-unusable material
        // is never stored as the update-channel trust anchor. (Chain
        // verification and the (tenant, env) identity binding are enforced
        // server-side at mTLS use time in Phase 2.)
        greentic_update::tls::build_mtls_client(&greentic_update::tls::MtlsConfig {
            ca_pem: enrollment.ca_pem.clone(),
            client_cert_pem: enrollment.client_cert_pem.clone(),
            client_key_pem: enrollment.client_key_pem.clone(),
        })
        .map_err(|e| {
            OpError::Conflict(format!("CA response is not a usable mTLS identity: {e}"))
        })?;

        let stored = persist_enrollment(
            store,
            &env,
            &env_id,
            kind_path,
            &tenant,
            &ca_url,
            &enrollment,
        )?;

        let outcome = OpOutcome::new(
            NOUN,
            "enroll",
            json!({
                "environment_id": env_id.as_str(),
                "tenant": tenant,
                "serial": enrollment.serial,
                "not_after": enrollment.not_after,
                "secrets_kind": secrets.kind.to_string(),
                "stored": stored,
            }),
        );
        Ok((outcome, super::AuditGens::NONE))
    })
}

/// Write the enrolled material into the env secrets backend. Returns the list of
/// `{name, store_uri}` written, for the outcome. Recoverable by re-running
/// `enroll` (the single write overwrites).
fn persist_enrollment(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
    kind_path: &str,
    tenant: &str,
    ca_url: &str,
    enrollment: &greentic_update::enroll::Enrollment,
) -> Result<Vec<Value>, OpError> {
    // The whole identity is written as ONE secret, so key and certificate always
    // flip together: there is no inter-key window in which a re-enrollment could
    // leave the new private key paired with the previous certificate. A single
    // put is as atomic as the dev-store / Vault backends allow; on failure the
    // prior identity is left intact and `enroll` can simply be re-run.
    let identity = StoredIdentity {
        client_key_pem: enrollment.client_key_pem.clone(),
        client_cert_pem: enrollment.client_cert_pem.clone(),
        ca_pem: enrollment.ca_pem.clone(),
        ca_url: ca_url.to_string(),
    };
    let value = serde_json::to_string(&identity)
        .map_err(|e| OpError::Conflict(format!("serialize update-channel identity: {e}")))?;
    let rel_path = tls_rel_path(tenant, IDENTITY_NAME);
    let (store_uri, _extra) = put_env_secret(store, env, env_id, kind_path, &rel_path, &value)?;
    Ok(vec![json!({"name": IDENTITY_NAME, "store_uri": store_uri})])
}

/// Read the enrolled mTLS identity for `env_id`. `Ok(None)` when the env holds no
/// enrollment (deny-by-default: an absent secret is "not enrolled", not an
/// error). A present-but-unparseable blob is a hard error — the store never
/// silently degrades a corrupt identity into "not enrolled".
fn load_identity(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
    kind_path: &str,
    tenant: &str,
) -> Result<Option<StoredIdentity>, OpError> {
    let rel = tls_rel_path(tenant, IDENTITY_NAME);
    let (value, _uri, _extra) = get_env_secret(store, env, env_id, kind_path, &rel)?;
    match value {
        None => Ok(None),
        Some(raw) => {
            let identity = serde_json::from_str::<StoredIdentity>(&raw).map_err(|e| {
                OpError::Conflict(format!("stored update-channel identity is corrupt: {e}"))
            })?;
            Ok(Some(identity))
        }
    }
}

/// `op updates status` — report whether the env holds an enrolled update-channel
/// certificate and, if so, its serial + validity window. Read-only (not
/// audited), so it never reveals the private key.
pub fn status(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<UpdatesStatusPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "status", status_schema()));
    }
    let payload = resolve_payload::<UpdatesStatusPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let env = store.load(&env_id)?;
    let secrets = require_secrets_pack(&env, &env_id)?;
    let kind_path = secrets.kind.path();
    let tenant = require_tenant(&env, &env_id)?;

    let identity = load_identity(store, &env, &env_id, kind_path, &tenant)?;

    let body = match identity {
        None => json!({
            "environment_id": env_id.as_str(),
            "tenant": tenant,
            "secrets_kind": secrets.kind.to_string(),
            "enrolled": false,
        }),
        Some(id) => {
            let info = greentic_update::tls::parse_cert_info(&id.client_cert_pem).map_err(|e| {
                OpError::Conflict(format!(
                    "stored update-channel certificate is unparseable: {e}"
                ))
            })?;
            json!({
                "environment_id": env_id.as_str(),
                "tenant": tenant,
                "secrets_kind": secrets.kind.to_string(),
                "enrolled": true,
                "serial": info.serial_hex,
                "not_before_epoch": info.not_before_epoch,
                "not_after_epoch": info.not_after_epoch,
            })
        }
    };
    Ok(OpOutcome::new(NOUN, "status", body))
}

/// `op updates get` — pull a signed update plan (over the enrolled mTLS channel
/// or from a local file), verify it against the env trust root, run the
/// downgrade + compatibility gates, and admit it to the update staging tree.
///
/// Read-only with respect to the environment store — the only writes are into
/// the update staging tree, which keeps its own audit ledger — so this verb is
/// not wrapped in `audit_and_record` (like `status`).
///
/// The gates run *before* any staging write, so a rejected plan leaves nothing
/// half-staged. Declared artifacts are then fetched into the staging tree
/// (through the content-addressed `DistClient`, with `put_artifact` re-verifying
/// each digest fail-closed) and the plan is promoted `downloading → inbox →
/// staged`; a plan with no artifacts promotes straight away. The outcome's
/// `stage` field reports where the plan landed.
pub fn get(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<UpdatesGetPayload>,
) -> Result<OpOutcome, OpError> {
    get_impl(store, flags, payload, None)
}

/// Body of [`get`], with an optional staging-root override so tests can point
/// the FSM at a tempdir instead of `~/.greentic/updates` (the crate forbids
/// `unsafe`, so an env-var override is not available in tests).
fn get_impl(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<UpdatesGetPayload>,
    updates_root_override: Option<&std::path::Path>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "get", get_schema()));
    }
    let payload = resolve_payload::<UpdatesGetPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let env = store.load(&env_id)?;

    // 1. Source the signed plan bytes (mTLS pull or local file pair).
    let (plan_bytes, envelope_bytes) = load_plan_source(store, &env, &env_id, &payload)?;

    // 2. Verify the DSSE signature + subject digest against the env trust root.
    //    Closed-by-default: an env with no trusted keys rejects every plan.
    let env_dir = store.env_dir(&env_id)?;
    let trust = store_trust_root::load(&env_dir)?;
    let verified = greentic_update::plan::verify_update_plan(&plan_bytes, &envelope_bytes, &trust)
        .map_err(|e| OpError::Conflict(format!("update plan failed verification: {e}")))?;

    // 3. The plan must target THIS environment. Two identities must agree — the
    //    plan header (`plan.env_id`) AND the signed desired-state manifest it
    //    carries (`target.environment.id`). Both are under the DSSE signature, so
    //    a divergence means a buggy/compromised signer produced a plan whose
    //    header names this env while its manifest reconciles another; fail closed
    //    on either mismatch before touching the staging tree.
    if verified.plan.env_id != env_id.as_str() {
        return Err(OpError::InvalidArgument(format!(
            "plan targets env `{}`, not `{env_id}`",
            verified.plan.env_id
        )));
    }
    let manifest: EnvManifest =
        serde_json::from_value(verified.plan.target.clone()).map_err(|e| {
            OpError::InvalidArgument(format!(
                "plan target is not a valid {ENV_MANIFEST_SCHEMA_V1}: {e}"
            ))
        })?;
    if manifest.environment.id != env_id.as_str() {
        return Err(OpError::InvalidArgument(format!(
            "plan target manifest names env `{}`, not `{env_id}`",
            manifest.environment.id
        )));
    }

    // 4. Admit to staging under a single lock hold — or RESUME an
    //    already-admitted identical plan. The downgrade guard (monotonic
    //    sequence) and the compatibility gate run INSIDE `begin_checked`'s
    //    admission predicate, atomically with the begin writes, so a concurrent
    //    updater on the same env cannot change the applied set between the check
    //    and the commit (closes the gate/begin race from #417's review). Both
    //    gates run before any staging write, so a rejected plan leaves nothing
    //    half-staged.
    //
    //    Loading an existing same-digest plan first makes `get` idempotent /
    //    resumable: `begin_checked` alone errors `PlanExists` on re-run, so a
    //    crash after admission but before the promotion transitions would strand
    //    the plan. A same-id plan with a DIFFERENT digest is refused (a distinct
    //    plan must not reuse the id).
    let root = open_updates_root(&env_id, updates_root_override)?;
    let staged = admit_or_resume(&root, &verified, &plan_bytes, &envelope_bytes)?;

    // 6. Fetch every declared artifact into the staging tree, then promote to
    //    `staged`. A plan with no artifacts promotes straight away. Both paths
    //    are idempotent/resumable: a plan already past `downloading` is returned
    //    as-is (a completed prior run), and `put_artifact` is content-addressed
    //    and fail-closed on a digest mismatch.
    let artifacts_total = verified.plan.artifacts.len();
    let final_stage = if artifacts_total == 0 {
        advance_to_staged(&staged)?
    } else {
        let fetcher = DistArtifactFetcher::new();
        download_and_stage(
            &staged,
            &verified.plan.artifacts,
            &fetcher,
            RetryPolicy::default(),
        )?
    };

    Ok(OpOutcome::new(
        NOUN,
        "get",
        json!({
            "environment_id": env_id.as_str(),
            "plan_id": verified.plan.plan_id,
            "sequence": verified.plan.sequence,
            "plan_sha256": verified.plan_sha256,
            "verified_key_ids": verified.verified_key_ids,
            "stage": final_stage.as_str(),
            "artifacts_total": artifacts_total,
            "plan_dir": staged.dir().display().to_string(),
        }),
    ))
}

/// Open the per-env update staging root (`GREENTIC_UPDATES_DIR` or
/// `~/.greentic/updates/<env_id>`).
fn open_updates_root(
    env_id: &EnvId,
    root_override: Option<&std::path::Path>,
) -> Result<greentic_update::staging::UpdatesRoot, OpError> {
    let opened = match root_override {
        Some(root) => greentic_update::staging::UpdatesRoot::open_in(root, env_id.as_str()),
        None => greentic_update::staging::UpdatesRoot::open(env_id.as_str()),
    };
    opened.map_err(|e| OpError::Conflict(format!("open update staging root: {e}")))
}

/// The `begin_checked` admission predicate for `op updates get`: the downgrade
/// guard (monotonic sequence vs the applied set) and the compatibility gate,
/// evaluated against the lock-held [`AdmissionFacts`] snapshot so both run
/// atomically with the begin writes. Returns the `OpError` a rejection surfaces
/// as; the caller maps `BeginCheckedError::Rejected(op)` straight back to it.
///
/// [`AdmissionFacts`]: greentic_update::staging::AdmissionFacts
fn admit_plan(
    verified: &greentic_update::plan::VerifiedUpdatePlan,
    facts: &greentic_update::staging::AdmissionFacts,
) -> Result<(), OpError> {
    // Downgrade guard: the plan's sequence must be newer than the highest
    // already-applied sequence (read under the staging lock).
    greentic_update::plan::ensure_not_downgrade(&verified.plan, facts.latest_applied_sequence)
        .map_err(|e| OpError::Conflict(format!("update plan rejected: {e}")))?;
    // Compatibility gate against the applied set + local runtime facts.
    let runtime_facts = greentic_update::plan::RuntimeFacts {
        // The operator CLI is released in lockstep with the runtime it manages,
        // so its own version is the runtime-version floor we can assert locally.
        runtime_version: Some(env!("CARGO_PKG_VERSION")),
        // The operator does not observe the live component ABI; a plan pinning
        // `compat.abi` is left to apply-time (Phase 3), where the running runtime
        // reports it. Unknown here ⇒ `check_compat` fails closed on an abi pin.
        abi: None,
        applied_plan_ids: &facts.applied_plan_ids,
    };
    greentic_update::plan::check_compat(&verified.plan.compat, &runtime_facts)
        .map_err(|e| OpError::Conflict(format!("update plan incompatible: {e}")))
}

/// Admit a verified plan to staging, or resume an identical already-staged one.
///
/// Fresh admission runs [`admit_plan`] inside `begin_checked`, so the downgrade
/// and compat gates are atomic with the begin writes. On RESUME (a same-digest
/// plan already present — the idempotent/crash-recovery path), admission is
/// **re-run** before any further promotion: a plan stranded at `downloading`/
/// `inbox` could otherwise be promoted after a newer plan was applied in the
/// interim, silently bypassing the downgrade guard `begin_checked` makes
/// authoritative. Terminal `failed`/`rejected` plans are refused (not resumed
/// as success); already-`staged`/`applying`/`applied` plans passed admission at
/// begin and are returned as-is.
///
/// The resume re-check is best-effort (not held under the staging lock — the
/// deployer can't; the atomic gate is the fresh `begin_checked`, and apply
/// re-checks downgrade). Single-operator use is unaffected.
fn admit_or_resume(
    root: &greentic_update::staging::UpdatesRoot,
    verified: &greentic_update::plan::VerifiedUpdatePlan,
    plan_bytes: &[u8],
    envelope_bytes: &[u8],
) -> Result<greentic_update::staging::StagedPlan, OpError> {
    use greentic_update::staging::UpdateStage;
    match root
        .load(&verified.plan.plan_id)
        .map_err(|e| OpError::Conflict(format!("load staged update plan: {e}")))?
    {
        Some(existing) => {
            if existing.plan_sha256() != verified.plan_sha256 {
                return Err(OpError::Conflict(format!(
                    "a different plan is already staged under id `{}`",
                    verified.plan.plan_id
                )));
            }
            let stage = existing
                .stage()
                .map_err(|e| OpError::Conflict(format!("read update staging stage: {e}")))?;
            match stage {
                // Terminal outcomes are not "resumable" — report, don't succeed.
                UpdateStage::Failed | UpdateStage::Rejected => Err(OpError::Conflict(format!(
                    "plan `{}` is already `{stage}`; not resuming",
                    verified.plan.plan_id
                ))),
                // Stranded mid-flight: re-gate against the CURRENT applied set
                // before resuming, so a newer applied plan invalidates it.
                UpdateStage::Downloading | UpdateStage::Inbox => {
                    admit_plan(verified, &current_admission_facts(root)?)?;
                    Ok(existing)
                }
                // Already admitted AND promoted — its gates ran at begin.
                UpdateStage::Staged | UpdateStage::Applying | UpdateStage::Applied => Ok(existing),
            }
        }
        None => root
            .begin_checked(verified, plan_bytes, envelope_bytes, |facts| {
                admit_plan(verified, facts)
            })
            .map_err(|e| match e {
                greentic_update::staging::BeginCheckedError::Rejected(op) => op,
                greentic_update::staging::BeginCheckedError::Staging(s) => {
                    OpError::Conflict(format!("stage update plan: {s}"))
                }
            }),
    }
}

/// Snapshot the applied-plan set for a resume-time re-gate (best-effort — not
/// under the staging lock; the atomic gate is `begin_checked`).
fn current_admission_facts(
    root: &greentic_update::staging::UpdatesRoot,
) -> Result<greentic_update::staging::AdmissionFacts, OpError> {
    let applied: Vec<_> = root
        .list()
        .map_err(|e| OpError::Conflict(format!("list staged update plans: {e}")))?
        .into_iter()
        .filter(|s| s.stage == greentic_update::staging::UpdateStage::Applied)
        .collect();
    Ok(greentic_update::staging::AdmissionFacts {
        latest_applied_sequence: applied.iter().map(|s| s.sequence).max(),
        applied_plan_ids: applied.into_iter().map(|s| s.plan_id).collect(),
    })
}

/// Promote a plan to `staged`, from wherever it currently sits (`downloading` →
/// `inbox` → `staged`). Idempotent: an already-`staged` plan is a no-op, so a
/// resumed partial run converges. Non-`downloading`/`inbox` stages (already
/// `staged`, or terminal) are left untouched. Used by both the zero-artifact
/// path and after a successful artifact download.
fn advance_to_staged(
    staged: &greentic_update::staging::StagedPlan,
) -> Result<greentic_update::staging::UpdateStage, OpError> {
    use greentic_update::staging::UpdateStage;
    let mut stage = staged
        .stage()
        .map_err(|e| OpError::Conflict(format!("read update staging stage: {e}")))?;
    if stage == UpdateStage::Downloading {
        stage = staged
            .transition(UpdateStage::Inbox)
            .map_err(|e| OpError::Conflict(format!("advance update staging: {e}")))?
            .stage;
    }
    if stage == UpdateStage::Inbox {
        stage = staged
            .transition(UpdateStage::Staged)
            .map_err(|e| OpError::Conflict(format!("advance update staging: {e}")))?
            .stage;
    }
    Ok(stage)
}

/// `op updates apply` — apply a STAGED update plan to its environment
/// (Phase 3 of the Greentic updater). **Mutation.**
///
/// The staged plan (from `op updates get`) is re-verified end-to-end off the
/// on-disk staging tree *before* any environment mutation — DSSE signature,
/// per-artifact checksums, the tamper cross-check against the write-time
/// digest, the target-env identity, and the downgrade + compat gates against
/// the current applied set. Re-verification is defense-in-depth: the plan was
/// verified at `get`, but the bytes sitting on disk are untrusted at apply
/// time.
///
/// A passing plan is then applied under a whole-env snapshot: `staged →
/// applying`, snapshot the environment (P0b), drive the declarative
/// [`env_apply`](super::env_apply::apply) pipeline with the plan's signed
/// target manifest, and on success `applying → applied` (so
/// `latest_applied_sequence` advances). On ANY apply failure the pre-apply
/// snapshot is restored and the plan is marked `failed`. A plan stranded in
/// `applying` from a prior crash is failed closed (re-stage via `op updates
/// get`). The mutating region runs inside `audit_and_record`.
///
/// Scope of this increment: **content add/update only** (the manifest is
/// upsert-applied — resource removal/prune is deferred). Success means the env
/// store converged (`env_apply`'s internal verify); live runtime health is not
/// gated here (the deployer cannot reach `greentic-start`'s health gate). The
/// binary self-update track is not built; a plan carrying binaries would fail
/// the manifest parse. Fail-closed guards on the target manifest (see
/// [`check_applyable_manifest`]): bundles must be `bundle_digest`-pinned (so
/// `env_apply` verifies the applied bytes against the signed plan), and
/// `secrets[]` / `messaging_endpoints[]` (which write dev-store secret material)
/// are applyable only when the effective `Secrets` sink is the P0b-snapshotted
/// dev-store, so a failed apply can roll those writes back. Concurrent apply on
/// one env is single-flight: `begin_apply_checked`
/// admits at most one plan into `applying` per env under the staging lock,
/// rejecting a second, and runs the downgrade/compat re-gate atomically with the
/// `staged → applying` transition.
pub fn apply_updates(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<ApplyUpdatesPayload>,
) -> Result<OpOutcome, OpError> {
    apply_updates_impl(store, flags, payload, None)
}

/// Body of [`apply_updates`], with an optional staging-root override so tests
/// can point the FSM at a tempdir instead of `~/.greentic/updates`.
fn apply_updates_impl(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<ApplyUpdatesPayload>,
    updates_root_override: Option<&std::path::Path>,
) -> Result<OpOutcome, OpError> {
    use greentic_update::staging::{RetentionPolicy, UpdateStage};

    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "apply", apply_updates_schema()));
    }
    let payload = resolve_payload::<ApplyUpdatesPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;

    // Load the staged plan handle (read-only). A missing plan is a plain
    // NotFound — nothing to apply.
    let root = open_updates_root(&env_id, updates_root_override)?;
    let staged = root
        .load(&payload.plan_id)
        .map_err(|e| OpError::Conflict(format!("load staged update plan: {e}")))?
        .ok_or_else(|| {
            OpError::NotFound(format!(
                "no staged plan `{}` under env `{env_id}`; run `op updates get` first",
                payload.plan_id
            ))
        })?;

    // Stage gate. Only a `staged` plan is applicable. An `applying` plan is
    // NOT auto-failed here: the staging lock is not held across the whole apply
    // (env_apply's own flock serializes the mutation), so `applying` cannot be
    // told apart from an *active* concurrent apply of the same plan — failing it
    // would let that apply mutate the env yet be unable to reach `applied`,
    // leaving the env changed while `latest_applied_sequence` never advances. So
    // return a retryable conflict and touch nothing; a genuinely stuck plan is
    // recovered explicitly, not by a racy self-heal. Any other stage (still
    // downloading, or already terminal) is a plain argument error.
    let stage = staged
        .stage()
        .map_err(|e| OpError::Conflict(format!("read update staging stage: {e}")))?;
    match stage {
        UpdateStage::Staged => {}
        UpdateStage::Applying => {
            return Err(OpError::Conflict(format!(
                "plan `{}` is already `applying` on env `{env_id}` (another apply may be in \
                 progress, or a prior one did not finish); retry once it settles",
                payload.plan_id
            )));
        }
        other => {
            return Err(OpError::InvalidArgument(format!(
                "plan `{}` is `{other}`, not `staged`; only a staged plan can be applied",
                payload.plan_id
            )));
        }
    }

    // Re-verify the staged plan bytes off disk (DSSE + tamper cross-check +
    // target-env identity). A rejected plan is dead — mark it `rejected`.
    let verified = match reverify_staged(store, &staged, &env_id) {
        Ok(v) => v,
        Err(e) => {
            let _ = staged.transition(UpdateStage::Rejected);
            return Err(e);
        }
    };

    // `op updates apply` converges CONTENT (artifacts + target bundles) only. A
    // plan may also carry binary artifacts, which are installed by the
    // greentic-start update receiver, not by this verb — warn so an "applied"
    // result is never read as "binary installed", and a binary-only plan-build
    // output is not silently applied as a no-op success.
    if !verified.plan.binaries.is_empty() {
        tracing::warn!(
            env_id = %env_id,
            binary_count = verified.plan.binaries.len(),
            "update plan carries binary artifact(s) that `op updates apply` does not \
             install; binary self-update is applied by the greentic-start update receiver"
        );
    }

    // The downgrade + compat re-gate moves INTO the `begin_apply_checked`
    // predicate below, so it runs atomically with the `staged → applying`
    // transition against a lock-held applied-set snapshot (closing the TOCTOU
    // where a newer plan applies between the re-gate and the transition).

    // Re-verify every declared artifact's on-disk checksum (fail closed), and
    // record each verified artifact's content-addressed blob path keyed by its
    // digest, so bundle entries can be materialized from the local staged set
    // below (no network re-fetch at apply time).
    let mut staged_blobs: BTreeMap<String, PathBuf> = BTreeMap::new();
    for artifact in &verified.plan.artifacts {
        if let Err(e) = staged.verify_artifact_on_disk(artifact) {
            let _ = staged.transition(UpdateStage::Rejected);
            return Err(OpError::Conflict(format!(
                "staged artifact `{}` failed integrity re-check: {e}",
                artifact.name
            )));
        }
        // Infallible after the verify above (same digest validation), but keep
        // it fail-closed rather than unwrapping.
        let blob = staged.artifact_blob_path(artifact).map_err(|e| {
            OpError::Conflict(format!(
                "resolve staged blob path for artifact `{}`: {e}",
                artifact.name
            ))
        })?;
        staged_blobs.insert(artifact.digest.clone(), blob);
    }

    // The plan's signed target manifest drives the apply. Point its bundle
    // artifacts at the already-verified staged blobs so the apply runs from
    // local disk instead of re-fetching them from the network.
    let target = materialize_bundles(&verified.plan.target, &staged_blobs);
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "apply",
        target: json!({
            "environment_id": env_id.as_str(),
            "plan_id": verified.plan.plan_id,
            "sequence": verified.plan.sequence,
            "plan_sha256": verified.plan_sha256,
        }),
        // Applying the same plan twice is a no-op via the FSM (a second apply
        // hits the terminal-stage gate); key audit dedup on the plan id.
        idempotency_key: Some(verified.plan.plan_id.clone()),
    };
    audit_and_record(store, ctx, |committed| {
        // Atomically admit this plan into `applying` under one staging-lock hold:
        // the downgrade/compat re-gate runs against a race-free applied-set
        // snapshot, a second in-flight apply is rejected (single-flight), and the
        // `staged → applying` transition commits — all before the lock releases.
        // This closes the concurrent-apply TOCTOU the best-effort guard only
        // narrowed; env_apply's own per-env store flock still serializes the
        // actual mutation below.
        match root.begin_apply_checked(&verified.plan.plan_id, |facts| admit_plan(&verified, facts))
        {
            Ok(_applying) => {}
            Err(greentic_update::staging::BeginApplyError::Rejected(e)) => {
                // The downgrade/compat re-gate rejected the plan (a newer plan
                // applied since staging) — it's dead. Nothing was mutated.
                let _ = staged.transition(UpdateStage::Rejected);
                return Err(e);
            }
            Err(greentic_update::staging::BeginApplyError::AlreadyApplying {
                applying, ..
            }) => {
                return Err(OpError::Conflict(format!(
                    "another update plan (`{applying}`) is already applying to env `{env_id}`; \
                     apply is single-flight per environment"
                )));
            }
            Err(greentic_update::staging::BeginApplyError::Staging(s)) => {
                // A staging error is usually pre-commit (the target left `staged`
                // between the pre-check and the lock, or a marker is corrupt —
                // nothing mutated). But begin_apply_checked writes `state.json`
                // = `applying` BEFORE appending its audit line, so an audit-append
                // failure surfaces here AFTER the transition already committed.
                // Re-read the stage: if this plan reached `applying`, the state is
                // durable, so mark the op committed for the audit ledger rather
                // than mis-reporting it as non-mutating.
                if staged
                    .stage()
                    .map(|st| st == UpdateStage::Applying)
                    .unwrap_or(false)
                {
                    committed.mark_committed();
                }
                return Err(OpError::Conflict(format!("apply admission failed: {s}")));
            }
        }
        // `applying` is now committed on disk, so every path below must be
        // fail-closed for the audit ledger.
        committed.mark_committed();

        // Snapshot the whole env BEFORE any mutation. If this fails, nothing
        // was mutated — fail the plan, no restore needed.
        let snap_id = match snapshot_environment(store, &env_id) {
            Ok(id) => id,
            Err(e) => {
                let _ = staged.transition(UpdateStage::Failed);
                return Err(e.into());
            }
        };

        // Drive the declarative apply pipeline with the signed target manifest.
        match run_manifest_apply(store, &target) {
            Ok(apply_outcome) => {
                // Build the success outcome body. Shared by the normal-success
                // path AND the Case-A recovery (state reached Applied but the
                // audit-append failed), so it lives in a closure to stay DRY.
                let build_success_outcome = || {
                    let mut body = json!({
                        "environment_id": env_id.as_str(),
                        "plan_id": verified.plan.plan_id,
                        "sequence": verified.plan.sequence,
                        "plan_sha256": verified.plan_sha256,
                        "snapshot_id": snap_id.to_string(),
                        "stage": UpdateStage::Applied.as_str(),
                        "apply_result": apply_outcome.result,
                    });
                    // Surface any binary artifacts this content apply did NOT
                    // install, so the "applied" result is never misread as a
                    // completed binary self-update (those are applied by the
                    // greentic-start receiver).
                    if !verified.plan.binaries.is_empty() {
                        let not_applied: Vec<Value> = verified
                            .plan
                            .binaries
                            .iter()
                            .map(|b| {
                                json!({"name": b.name, "version": b.version, "target": b.target})
                            })
                            .collect();
                        body["binaries_not_applied"] = Value::Array(not_applied);
                    }
                    let outcome = OpOutcome::new(NOUN, "apply", body);
                    Ok((outcome, super::AuditGens::NONE))
                };

                // Allow test code to inject a fault immediately before the
                // applying -> applied transition, so the Case-B honest-error
                // branch is exercisable.
                #[cfg(test)]
                run_pre_applied_transition_hook();

                // Retry the applying -> applied transition up to 2 attempts
                // with a 200ms sleep between. If the transition persistently
                // fails, re-read the stage: if it already reached Applied
                // (Case A: state.json committed but audit-append failed), take
                // the success path. Otherwise (Case B: state.json stuck at
                // Applying), return an honest error stating the env content IS
                // applied and pointing at `op updates recover`.
                for attempt in 0..2u8 {
                    match staged.transition(UpdateStage::Applied) {
                        Ok(_) => {
                            // Best-effort retention of terminal plans (never evicts active).
                            let _ = root.apply_retention(&RetentionPolicy { keep_terminal: 5 });
                            return build_success_outcome();
                        }
                        Err(e) => {
                            if attempt == 0 {
                                tracing::warn!(
                                    plan_id = %verified.plan.plan_id,
                                    error = %e,
                                    "applying -> applied transition failed; retrying in 200ms"
                                );
                                std::thread::sleep(std::time::Duration::from_millis(200));
                            }
                            // Second attempt failed — fall through to re-read.
                        }
                    }
                }

                // Persistent failure. Re-read the on-disk stage to distinguish
                // Case A (state IS Applied, audit-append gap) from Case B
                // (state stuck at Applying).
                match staged.stage() {
                    Ok(UpdateStage::Applied) => {
                        // Case A: the state.json write committed but the
                        // audit-append (or a subsequent retry's lock acquire)
                        // failed. The FSM is correct — take the success path.
                        let _ = root.apply_retention(&RetentionPolicy { keep_terminal: 5 });
                        build_success_outcome()
                    }
                    stage_result => {
                        // Case B: state.json did not reach Applied — either
                        // stuck (likely Applying) or unreadable. The env
                        // content IS applied, but the FSM marker did not
                        // advance. Do NOT restore the snapshot — the env is
                        // correct. Return an honest error with recovery
                        // instructions.
                        let detail = match stage_result {
                            Ok(s) => format!(" (current stage: `{}`)", s.as_str()),
                            Err(e) => format!(" and the current stage is unreadable: {e}"),
                        };
                        Err(OpError::Conflict(format!(
                            "plan `{}` content was applied successfully, but the staging \
                             marker could not advance to `applied`{}; \
                             the environment is correct — run \
                             `op updates recover --force` to un-stick the marker, then \
                             re-stage with `op updates get` if sequence tracking matters",
                            verified.plan.plan_id, detail,
                        )))
                    }
                }
            }
            Err(apply_err) => {
                // Roll the whole env back to the pre-apply snapshot, then fail
                // the plan. The plan is dead either way, but the surfaced error
                // must tell the TRUTH about whether the rollback actually
                // completed — never claim "restored" when restore failed and the
                // env may be partially applied.
                let restored = restore_environment(store, &env_id, &snap_id);
                let _ = staged.transition(UpdateStage::Failed);
                match restored {
                    Ok(()) => Err(OpError::Conflict(format!(
                        "apply of plan `{}` failed; environment rolled back to snapshot `{snap_id}`: \
                         {apply_err}",
                        verified.plan.plan_id
                    ))),
                    Err(restore_err) => {
                        tracing::error!(
                            env_id = %env_id,
                            snapshot_id = %snap_id,
                            apply_error = %apply_err,
                            restore_error = %restore_err,
                            "apply-updates rollback FAILED; environment may be partially applied"
                        );
                        Err(OpError::Conflict(format!(
                            "apply of plan `{}` failed AND automatic rollback FAILED; the \
                             environment may be partially applied — manual recovery is required \
                             from snapshot `{snap_id}`. apply error: {apply_err}; rollback error: \
                             {restore_err}",
                            verified.plan.plan_id
                        )))
                    }
                }
            }
        }
    })
}

/// `op updates recover` — force-fail a plan stranded in `applying` by a crashed
/// applier (Phase 3.1 of the Greentic updater). **Mutation.**
///
/// `op updates apply` deliberately refuses to auto-fail an `applying` plan: the
/// staging lock is not held across the whole apply (env_apply's own flock
/// serializes the mutation), so on disk a *crashed* applier and an *active*
/// concurrent apply are indistinguishable — auto-failing the marker could strand
/// a live apply (env mutated, plan `failed`, `latest_applied_sequence` never
/// advances). `recover` is the explicit operator escape hatch for the crashed
/// case: it force-transitions `applying → failed` (a legal FSM edge) under the
/// staging lock, and requires `--force` so the operator affirms the applier is
/// genuinely dead.
///
/// Scope: this un-sticks the update FSM only. It does **not** roll back any
/// partial environment change the interrupted apply may have made — the P0b
/// snapshot id is not durably linked to the plan, so a safe automated rollback is
/// not possible here. The success outcome names the env's `snapshots/` directory
/// for manual restore, and re-running `op updates get` re-stages the plan for a
/// clean apply.
pub fn recover_updates(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<RecoverUpdatesPayload>,
    force: bool,
) -> Result<OpOutcome, OpError> {
    recover_updates_impl(store, flags, payload, force, None)
}

/// Body of [`recover_updates`], with an optional staging-root override so tests
/// can point the FSM at a tempdir instead of `~/.greentic/updates`.
fn recover_updates_impl(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<RecoverUpdatesPayload>,
    force: bool,
    updates_root_override: Option<&std::path::Path>,
) -> Result<OpOutcome, OpError> {
    use greentic_update::staging::UpdateStage;

    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "recover", recover_schema()));
    }
    let payload = resolve_payload::<RecoverUpdatesPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;

    // Load the staged plan handle (read-only). A missing plan is a plain
    // NotFound — nothing to recover.
    let root = open_updates_root(&env_id, updates_root_override)?;
    let staged = root
        .load(&payload.plan_id)
        .map_err(|e| OpError::Conflict(format!("load staged update plan: {e}")))?
        .ok_or_else(|| {
            OpError::NotFound(format!(
                "no staged plan `{}` under env `{env_id}`; nothing to recover",
                payload.plan_id
            ))
        })?;

    // Stage gate. Only an `applying` plan is recoverable. Every other stage is an
    // argument error with a stage-specific hint — nothing is mutated, nothing is
    // audited (this mirrors how `apply` gates before its audited region).
    let state = staged
        .state()
        .map_err(|e| OpError::Conflict(format!("read update staging state: {e}")))?;
    match state.stage {
        UpdateStage::Applying => {}
        UpdateStage::Staged => {
            return Err(OpError::InvalidArgument(format!(
                "plan `{}` is `staged`, not `applying`; nothing to recover — apply it with \
                 `op updates apply`",
                payload.plan_id
            )));
        }
        terminal @ (UpdateStage::Applied | UpdateStage::Failed | UpdateStage::Rejected) => {
            return Err(OpError::InvalidArgument(format!(
                "plan `{}` is already `{terminal}` (terminal); nothing to recover",
                payload.plan_id
            )));
        }
        staging @ (UpdateStage::Downloading | UpdateStage::Inbox) => {
            return Err(OpError::InvalidArgument(format!(
                "plan `{}` is `{staging}` (still staging); nothing was applied, so there is \
                 nothing to recover — re-run `op updates get`",
                payload.plan_id
            )));
        }
    }

    // The instant the plan entered `applying` — the operator's cue for whether a
    // live apply is plausible (seconds ago) or the applier is long dead.
    let applying_since = state.updated_at.to_rfc3339();

    // Fail closed unless the operator explicitly asserts the applier is dead. On
    // disk an `applying` plan cannot be told apart from a live concurrent apply,
    // and force-failing a live apply would strand it (env mutated, plan `failed`,
    // sequence never advanced). `--force` is that assertion.
    if !force {
        return Err(OpError::Conflict(format!(
            "plan `{}` is `applying` on env `{env_id}` (since {applying_since}); recover \
             force-fails it to `failed`, which is UNSAFE if an apply is genuinely in progress. \
             If you have confirmed no apply is running for this plan, re-run with `--force`",
            payload.plan_id
        )));
    }

    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "recover",
        target: json!({
            "environment_id": env_id.as_str(),
            "plan_id": payload.plan_id,
            "previous_stage": UpdateStage::Applying.as_str(),
            "applying_since": applying_since,
        }),
        // Recovering the same plan twice is a no-op: the second call hits the
        // terminal-stage gate above (now `failed`) before reaching this mutation.
        idempotency_key: Some(payload.plan_id.clone()),
    };
    audit_and_record(store, ctx, |committed| {
        // The single mutation: force the stranded plan to `failed` under the
        // staging lock, which re-reads the on-disk stage before validating the
        // `applying → failed` edge (safe against a concurrent transition).
        //
        // `transition` writes `state.json` BEFORE appending its own staging audit
        // line, so an audit-append failure returns `Err` AFTER `failed` already
        // committed. Mirror the apply-admission handling: on error, re-read the
        // stage; if the plan is now `failed`, the mutation is durable, so mark the
        // op committed — the deployer audit boundary must stay fail-closed rather
        // than demote the failure to best-effort.
        if let Err(e) = staged.transition(UpdateStage::Failed) {
            if staged
                .stage()
                .map(|s| s == UpdateStage::Failed)
                .unwrap_or(false)
            {
                committed.mark_committed();
            }
            return Err(OpError::Conflict(format!(
                "force-fail plan (applying → failed): {e}"
            )));
        }
        committed.mark_committed();
        let outcome = OpOutcome::new(
            NOUN,
            "recover",
            json!({
                "environment_id": env_id.as_str(),
                "plan_id": payload.plan_id,
                "previous_stage": UpdateStage::Applying.as_str(),
                "stage": UpdateStage::Failed.as_str(),
                "applying_since": applying_since,
                "note": "recover un-stuck the update FSM (applying → failed); it did NOT roll \
                         back any partial environment change from the interrupted apply. Inspect \
                         the environment and restore from a snapshot under <env_dir>/snapshots/ if \
                         needed. This plan id is now terminal (`failed`) and cannot be re-staged; \
                         retry by fetching a fresh plan with `op updates get`.",
            }),
        );
        Ok((outcome, super::AuditGens::NONE))
    })
}

/// `op updates config-set` — set the update-channel notification policy. Only
/// the fields supplied are changed; the rest keep their stored value. An absent
/// `update-channel.json` is seeded from `disabled` (deny-by-default), so the
/// first `config-set` is what turns the channel on.
pub fn config_set(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<UpdateConfigSetPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "config-set", config_set_schema()));
    }
    let payload = resolve_payload::<UpdateConfigSetPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;

    // Parse/validate every input BEFORE touching the store or the audit log, so
    // a malformed value is rejected fail-closed with nothing half-written.
    let parsed_action = payload
        .on_notify
        .as_deref()
        .map(|raw| {
            UpdateAction::parse(raw).ok_or_else(|| {
                OpError::InvalidArgument(format!(
                    "on_notify {raw:?} is not a valid action \
                     (expected `record-only`, `stage`, or `apply`)"
                ))
            })
        })
        .transpose()?;
    if let Some(secs) = payload.poll_interval_secs
        && secs < MIN_POLL_INTERVAL_SECS
    {
        return Err(OpError::InvalidArgument(format!(
            "poll_interval_secs {secs} is below the {MIN_POLL_INTERVAL_SECS}s floor"
        )));
    }
    let validated_plan_endpoint = payload
        .plan_endpoint
        .as_deref()
        .map(|raw| {
            let ep = raw.trim();
            if ep.is_empty() {
                // Reject fail-closed rather than silently no-op: an operator who
                // passes a blank value is trying to change something. To stop
                // polling, disable the channel; to repoint, pass a new URL.
                return Err(OpError::InvalidArgument(
                    "plan_endpoint must not be blank (to stop polling, disable \
                     the channel; to repoint, pass a new URL)"
                        .to_string(),
                ));
            }
            if !control_url_is_acceptable(ep) {
                return Err(OpError::InvalidArgument(format!(
                    "plan_endpoint {ep:?} is not an acceptable control URL \
                     (https required; http only to loopback)"
                )));
            }
            Ok(ep.to_string())
        })
        .transpose()?;
    let validated_stream_endpoint = payload
        .stream_endpoint
        .as_deref()
        .map(|raw| {
            let ep = raw.trim();
            if ep.is_empty() {
                return Err(OpError::InvalidArgument(
                    "stream_endpoint must not be blank (omit the flag to leave \
                     unchanged; unset derives from plan_endpoint)"
                        .to_string(),
                ));
            }
            if !control_url_is_acceptable(ep) {
                return Err(OpError::InvalidArgument(format!(
                    "stream_endpoint {ep:?} is not an acceptable control URL \
                     (https required; http only to loopback)"
                )));
            }
            Ok(ep.to_string())
        })
        .transpose()?;
    if !store.exists(&env_id)? {
        return Err(OpError::NotFound(format!(
            "environment `{env_id}` not found"
        )));
    }

    // Enabling without an explicit endpoint triggers the fleet-default write:
    // the operator is subscribing to the channel and hasn't said where to poll,
    // so we persist `DEFAULT_PLAN_ENDPOINT` (write-time, not read-time — see the
    // deploy-spec test `enabled_config_with_no_endpoint_resolves_plan_to_none`).
    let enabling_without_endpoint =
        payload.enabled == Some(true) && validated_plan_endpoint.is_none();

    let mut fields = Vec::new();
    if payload.enabled.is_some() {
        fields.push("enabled");
    }
    if parsed_action.is_some() {
        // One flag, two on-disk fields: `set_action` mirrors the action down to
        // the legacy `on_notify` so an older binary reads a safe policy.
        fields.push("on_update");
        fields.push("on_notify");
    }
    if payload.poll_interval_secs.is_some() {
        fields.push("poll_interval_secs");
    }
    if validated_plan_endpoint.is_some() || enabling_without_endpoint {
        fields.push("plan_endpoint");
    }
    if payload.push_enabled.is_some() {
        fields.push("push_enabled");
    }
    if validated_stream_endpoint.is_some() {
        fields.push("stream_endpoint");
    }

    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "config-set",
        target: json!({ "fields": fields }),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        // One locked transaction (mirrors `op config set` → `update_environment`):
        // hold the env flock across validate → read → merge → write so two
        // disjoint concurrent `config-set`s can't drop each other's fields, and
        // a corrupt/spoofed env directory (which `exists` alone would admit) is
        // rejected fail-closed before anything is written.
        let (cfg, defaulted_endpoint) = store.transact(
            &env_id,
            |locked| -> Result<(UpdateChannelConfig, bool), OpError> {
                // Validated Environment load under the lock (schema + env-id binding).
                locked.load()?;
                let mut cfg = locked
                    .load_update_channel()?
                    .unwrap_or_else(|| UpdateChannelConfig::disabled(env_id.clone()));
                if let Some(enabled) = payload.enabled {
                    cfg.enabled = Some(enabled);
                }
                if let Some(action) = parsed_action {
                    cfg.set_action(action);
                }
                if let Some(secs) = payload.poll_interval_secs {
                    cfg.poll_interval_secs = Some(secs);
                }
                let mut defaulted = false;
                if let Some(ep) = validated_plan_endpoint {
                    cfg.plan_endpoint = Some(ep);
                } else if enabling_without_endpoint && cfg.plan_endpoint.is_none() {
                    // No endpoint supplied, none stored, and the operator is
                    // enabling — persist the fleet default so the runtime has
                    // somewhere to poll. Write-time, not read-time.
                    cfg.plan_endpoint = Some(DEFAULT_PLAN_ENDPOINT.to_owned());
                    defaulted = true;
                }
                if let Some(pe) = payload.push_enabled {
                    cfg.push_enabled = Some(pe);
                }
                if let Some(ep) = validated_stream_endpoint {
                    cfg.stream_endpoint = Some(ep);
                }
                locked.save_update_channel(&cfg)?;
                Ok((cfg, defaulted))
            },
        )?;
        let mut view = config_view(&cfg);
        if defaulted_endpoint {
            // Make the defaulting visible: silently pointing a runtime at a
            // Greentic-operated URL is exactly the kind of thing that must
            // surface in the operator's output.
            view["defaulted_plan_endpoint"] = json!(DEFAULT_PLAN_ENDPOINT);
            view["note"] = json!(format!(
                "no plan_endpoint supplied; using fleet default: {DEFAULT_PLAN_ENDPOINT}"
            ));
        }
        let outcome = OpOutcome::new(NOUN, "config-set", view);
        Ok((outcome, super::AuditGens::NONE))
    })
}

/// `op updates config-show` — read the update-channel policy: the raw stored
/// fields plus the resolved effective values. Read-only, not audited.
pub fn config_show(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<UpdateConfigShowFilter>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "config-show", config_show_schema()));
    }
    let payload = resolve_payload::<UpdateConfigShowFilter>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    if !store.exists(&env_id)? {
        return Err(OpError::NotFound(format!(
            "environment `{env_id}` not found"
        )));
    }
    let cfg = store
        .load_update_channel(&env_id)?
        .unwrap_or_else(|| UpdateChannelConfig::disabled(env_id.clone()));
    Ok(OpOutcome::new(NOUN, "config-show", config_view(&cfg)))
}

/// Render an [`UpdateChannelConfig`] for an op outcome: the raw stored fields
/// plus the resolved effective values, so an operator sees both what is set and
/// what the runtime will actually do.
fn config_view(cfg: &UpdateChannelConfig) -> Value {
    json!({
        "environment_id": cfg.environment_id.as_str(),
        "enabled": cfg.enabled,
        // `on_notify` is the legacy mirror of `on_update`; both are reported raw
        // so an operator can see exactly what an older binary would read.
        "on_notify": cfg.on_notify.map(|a| a.as_str()),
        "on_update": cfg.on_update.map(|a| a.as_str()),
        "poll_interval_secs": cfg.poll_interval_secs,
        "plan_endpoint": cfg.plan_endpoint,
        "push_enabled": cfg.push_enabled,
        "stream_endpoint": cfg.stream_endpoint,
        "resolved": {
            "enabled": cfg.resolved_enabled(),
            "action": cfg.resolved_action().as_str(),
            "on_notify": cfg.resolved_on_notify().as_str(),
            "poll_interval_secs": cfg.resolved_poll_interval_secs(),
            "plan_endpoint": cfg.resolved_plan_endpoint(),
            "push_enabled": cfg.resolved_push_enabled(),
            "stream_endpoint": cfg.resolved_stream_endpoint(),
        }
    })
}

/// Re-verify a staged plan off its on-disk bytes: DSSE signature against the
/// env trust root, a hash cross-check against the write-time digest recorded in
/// `state.json` (catches a `plan.json` swapped after staging), and the
/// target-env identity (both the plan header and the signed manifest must name
/// this env). Returns the re-verified plan.
fn reverify_staged(
    store: &LocalFsStore,
    staged: &greentic_update::staging::StagedPlan,
    env_id: &EnvId,
) -> Result<greentic_update::plan::VerifiedUpdatePlan, OpError> {
    let plan_bytes = staged
        .plan_bytes()
        .map_err(|e| OpError::Conflict(format!("read staged plan bytes: {e}")))?;
    let envelope_bytes = staged
        .envelope_bytes()
        .map_err(|e| OpError::Conflict(format!("read staged plan envelope: {e}")))?;

    let env_dir = store.env_dir(env_id)?;
    let trust = store_trust_root::load(&env_dir)?;
    let verified = greentic_update::plan::verify_update_plan(&plan_bytes, &envelope_bytes, &trust)
        .map_err(|e| OpError::Conflict(format!("staged plan failed re-verification: {e}")))?;

    // The freshly-hashed plan bytes must match the digest captured at stage
    // time; a divergence means `plan.json` changed on disk since it was staged.
    if verified.plan_sha256 != staged.plan_sha256() {
        return Err(OpError::Conflict(format!(
            "staged plan `{}` hash changed since staging (tampered on disk?)",
            verified.plan.plan_id
        )));
    }
    // Target-env identity: the plan header AND the signed desired-state manifest
    // must both name this env (both are under the DSSE signature).
    if verified.plan.env_id != env_id.as_str() {
        return Err(OpError::InvalidArgument(format!(
            "staged plan targets env `{}`, not `{env_id}`",
            verified.plan.env_id
        )));
    }
    let manifest: EnvManifest =
        serde_json::from_value(verified.plan.target.clone()).map_err(|e| {
            OpError::InvalidArgument(format!(
                "plan target is not a valid {ENV_MANIFEST_SCHEMA_V1}: {e}"
            ))
        })?;
    if manifest.environment.id != env_id.as_str() {
        return Err(OpError::InvalidArgument(format!(
            "plan target manifest names env `{}`, not `{env_id}`",
            manifest.environment.id
        )));
    }
    // Fail closed on manifest content this increment cannot apply *safely*. The
    // dev-store-secret guard needs the env's `Secrets` binding, the env dir (to
    // check the dev-store files aren't symlinked off the tree), and whether the
    // dev-store is redirected off the tree by the override.
    let env = store.load(env_id)?;
    let dev_secrets_path_override =
        std::env::var_os(super::secrets::DEV_SECRETS_PATH_ENV).is_some();
    check_applyable_manifest(&env, &env_dir, &manifest, dev_secrets_path_override)?;
    Ok(verified)
}

/// Reject a target manifest whose apply/rollback this increment cannot yet
/// guarantee. These are fail-closed scope guards, not permanent limits:
///
/// - **dev-store secret side effects** — `env_apply` writes dev-store secret
///   material for `secrets[]` (a `put-secret` step) and for
///   `messaging_endpoints[]` (a telegram-class endpoint auto-provisions a
///   webhook secret). Those writes are rollback-safe only when they land in the
///   dev-store the P0b snapshot captures, so they're allowed **only** when the
///   effective `Secrets` sink is that dev-store — see
///   [`dev_store_secret_sink_is_snapshotted`]. (Audited against `env_apply`'s
///   `StepOp` execute arms: only `PutSecret` and `EndpointAdd` write dev-store
///   secrets.)
/// - **unpinned bundles** — require a `bundle_digest` on every bundle (and
///   revision). The digest is both the integrity pin and the key that
///   materializes the bundle from the verified staged blob set (see
///   [`materialize_bundles`]); `env_apply` re-verifies the applied bytes against
///   it. Unpinned / trust-on-first-use content has no staged blob to bind to and
///   can't be applied.
///
/// `dev_secrets_path_override` is `GREENTIC_DEV_SECRETS_PATH` presence, resolved
/// by the caller (the test harness cannot set process env vars safely).
fn check_applyable_manifest(
    env: &Environment,
    env_dir: &Path,
    manifest: &EnvManifest,
    dev_secrets_path_override: bool,
) -> Result<(), OpError> {
    // An update plan may not re-point the channel it arrived on. Honoring
    // `updates` here would let one signed plan redirect `plan_endpoint` at a
    // server of its choosing and thereby control every plan that follows — a
    // self-perpetuating takeover from a single mis-signed artifact. The channel
    // is operator-local state, set by `op env apply` or `op updates config-set`;
    // `op updates publish` strips the block at sign time, and this is the
    // fail-closed backstop for a plan built any other way.
    if manifest.updates.is_some() {
        return Err(OpError::InvalidArgument(
            "update plan target declares an `updates` block: a plan may not \
             re-point the update channel it arrived on. Configure the channel \
             with `op env apply` or `op updates config-set`."
                .to_string(),
        ));
    }
    // Same invariant for the trust root: a plan that seeds or rotates the
    // env's signing-key trust anchor would gain permanent signing authority.
    // Stripped at sign time by `strip_non_applyable_blocks`; refused here as
    // the fail-closed backstop.
    if manifest.trust_root.is_some() {
        return Err(OpError::InvalidArgument(
            "update plan target declares a `trust_root` block: a plan may not \
             re-point the trust root it is verified against. Configure the \
             trust root with `op env apply`."
                .to_string(),
        ));
    }
    // secrets[] / messaging_endpoints[] both write dev-store secret material;
    // allow them only when a failed apply's rollback (the P0b snapshot) would
    // undo those writes — i.e. the effective sink is the snapshotted dev-store.
    if (!manifest.secrets.is_empty() || !manifest.messaging_endpoints.is_empty())
        && let Err(reason) =
            dev_store_secret_sink_is_snapshotted(env, env_dir, manifest, dev_secrets_path_override)
    {
        return Err(dev_store_secret_err(reason));
    }
    for bundle in &manifest.bundles {
        match &bundle.revisions {
            Some(revisions) => {
                for rev in revisions {
                    if rev.bundle_digest.is_none() {
                        return Err(unpinned_bundle_err(&bundle.bundle_id, Some(&rev.name)));
                    }
                }
            }
            None => {
                if bundle.bundle_digest.is_none() {
                    return Err(unpinned_bundle_err(&bundle.bundle_id, None));
                }
            }
        }
    }
    Ok(())
}

/// Whether the dev-store secret writes `env_apply` performs for this manifest
/// would land in the dev-store the P0b snapshot captures (and can therefore be
/// rolled back). Returns `Err(reason)` naming the first way the sink escapes the
/// snapshot; `Ok(())` when it is fully covered. Four escapes:
///
/// 1. the env's current `Secrets` binding is a non-dev-store backend (e.g.
///    Vault) — those values live outside the snapshot;
/// 2. the manifest rebinds the `Secrets` slot to a non-dev-store kind —
///    `env_apply` applies `packs[]` before `secrets[]`, so the rebind takes
///    effect first and redirects the writes;
/// 3. `GREENTIC_DEV_SECRETS_PATH` redirects the dev-store off the env tree,
///    which the env-dir-relative snapshot cannot reach.
/// 4. a dev-store secrets file (or an ancestor under the env dir) is a symlink —
///    the snapshot follows the link on capture but restore's atomic rename-over
///    replaces the *link* with a regular file, so the external target keeps the
///    written secret; refuse rather than leak a write past rollback.
///
/// Accepted residuals (single-operator scope, not redesigned here): the binding
/// and the symlink state are read before `env_apply` takes its own env flock, so
/// a concurrent manual `op env` rebind (or symlink plant) between this check and
/// the apply reopens the hole (the same class as the apply re-gate race); and
/// the guard is uniform across `secrets[]` and `messaging_endpoints[]` even
/// though a Vault `EndpointAdd` only stamps a ref (a possible future loosening).
fn dev_store_secret_sink_is_snapshotted(
    env: &Environment,
    env_dir: &Path,
    manifest: &EnvManifest,
    dev_secrets_path_override: bool,
) -> Result<(), &'static str> {
    if !crate::cli::env::secrets_backend_is_dev_store(env) {
        return Err("the env's Secrets slot is bound to a non-dev-store backend");
    }
    if manifest_rebinds_secrets_off_dev_store(manifest) {
        return Err("the manifest rebinds the Secrets slot to a non-dev-store backend");
    }
    if dev_secrets_path_override {
        return Err(
            "GREENTIC_DEV_SECRETS_PATH redirects the dev-store off the snapshotted env tree",
        );
    }
    // Both dev-store candidate files must resolve through plain directories under
    // the env dir — a symlinked candidate (or ancestor) escapes the snapshot's
    // rollback (see condition 4). Fail closed on a symlink or any IO error.
    for rel in [
        crate::cli::secrets::DEV_STORE_RELATIVE,
        crate::cli::secrets::DEV_STORE_STATE_RELATIVE,
    ] {
        if crate::path_safety::assert_no_symlink_ancestors(env_dir, &env_dir.join(rel)).is_err() {
            return Err("a dev-store secrets file resolves through a symlink outside the env tree");
        }
    }
    Ok(())
}

/// True if the manifest's `packs[]` binds the `Secrets` slot to a kind whose
/// path is not the dev-store. An unparseable kind is treated as a rebind
/// (fail-closed); shape validation rejects it later regardless.
fn manifest_rebinds_secrets_off_dev_store(manifest: &EnvManifest) -> bool {
    manifest.packs.iter().any(|p| {
        p.slot == greentic_deploy_spec::CapabilitySlot::Secrets
            && greentic_deploy_spec::PackDescriptor::try_new(&p.kind)
                .map(|d| d.path() != crate::defaults::DEV_STORE_SECRETS_PATH)
                .unwrap_or(true)
    })
}

fn dev_store_secret_err(reason: &str) -> OpError {
    OpError::InvalidArgument(format!(
        "update plan target declares secrets[] or messaging_endpoints[], but {reason}; env_apply \
         writes dev-store secret material that the environment snapshot would not cover, so a \
         rollback could not undo it"
    ))
}

fn unpinned_bundle_err(bundle_id: &str, revision: Option<&str>) -> OpError {
    let target = match revision {
        Some(r) => format!("bundle `{bundle_id}` revision `{r}`"),
        None => format!("bundle `{bundle_id}`"),
    };
    OpError::InvalidArgument(format!(
        "update plan target {target} has no bundle_digest; update-plan bundles must be \
         digest-pinned so the applied content is verified against the signed plan"
    ))
}

/// Rewrite the target manifest's bundle artifact paths to point at the
/// content-addressed blobs already staged and integrity-verified for this plan,
/// so `env_apply` reads them off local disk instead of re-fetching from the
/// network at apply time. For every bundle (single-revision) or revision whose
/// `bundle_digest` is present in `staged_blobs`, its `bundle_path` is set to the
/// staged blob's absolute path. A `bundle_source_uri`, if present, is left
/// intact — it stays the boot-time pull ref for a K8s worker, which reads the
/// local `bundle_path` for the apply and the URI later. A bundle whose digest is
/// not staged is left untouched, so apply falls back to its declared remote
/// source exactly as before this pass existed.
fn materialize_bundles(target: &Value, staged_blobs: &BTreeMap<String, PathBuf>) -> Value {
    let mut target = target.clone();
    let Some(bundles) = target.get_mut("bundles").and_then(Value::as_array_mut) else {
        return target;
    };
    for bundle in bundles {
        match bundle.get_mut("revisions").and_then(Value::as_array_mut) {
            // Multi-revision: each revision carries its own digest + path.
            Some(revisions) => {
                for rev in revisions {
                    materialize_entry(rev, staged_blobs);
                }
            }
            // Single-revision: the digest + path live on the bundle itself.
            None => materialize_entry(bundle, staged_blobs),
        }
    }
    target
}

/// Point one bundle/revision object at its staged blob when its `bundle_digest`
/// is in `staged_blobs`. A digest with no staged blob is a no-op: the entry
/// keeps its declared source and apply pulls it remotely. That fall-through is
/// warn-logged because, in a plan whose whole point is offline apply, a bundle
/// that still has to reach the network is worth surfacing.
fn materialize_entry(entry: &mut Value, staged_blobs: &BTreeMap<String, PathBuf>) {
    let Some(digest) = entry.get("bundle_digest").and_then(Value::as_str) else {
        return;
    };
    match staged_blobs.get(digest) {
        Some(blob) => {
            // Absolute content-addressed path; `env_apply` reads it directly and
            // re-verifies the bytes against `bundle_digest` at deploy time.
            entry["bundle_path"] = Value::String(blob.to_string_lossy().into_owned());
        }
        None => {
            tracing::warn!(
                bundle_digest = %digest,
                "update bundle digest not in the staged set; apply will fall back to its \
                 declared remote source"
            );
        }
    }
}

/// Write the plan's signed target manifest to a temp file and drive the
/// declarative `env_apply` pipeline non-interactively (`--yes`). The temp file
/// is held alive until apply returns.
fn run_manifest_apply(store: &LocalFsStore, target: &Value) -> Result<OpOutcome, OpError> {
    use std::io::Write as _;

    let bytes = serde_json::to_vec(target)
        .map_err(|e| OpError::InvalidArgument(format!("serialize plan target manifest: {e}")))?;
    let mut tmp = tempfile::Builder::new()
        .prefix("greentic-update-target-")
        .suffix(".json")
        .tempfile()
        .map_err(|source| OpError::Io {
            path: PathBuf::from("<tempfile>"),
            source,
        })?;
    tmp.write_all(&bytes).map_err(|source| OpError::Io {
        path: tmp.path().to_path_buf(),
        source,
    })?;
    tmp.flush().map_err(|source| OpError::Io {
        path: tmp.path().to_path_buf(),
        source,
    })?;

    let apply_flags = OpFlags {
        schema_only: false,
        answers: Some(tmp.path().to_path_buf()),
    };
    let opts = super::env_apply::ApplyOptions {
        mode: super::env_apply::ApplyMode::Apply,
        updated_by: Some("apply-updates".to_string()),
        yes: true,
        non_interactive: true,
        ..Default::default()
    };
    super::env_apply::apply(store, &apply_flags, opts)
}

/// Fetches an update artifact's bytes by its declared `source`. A seam so the
/// download orchestration is unit-testable without a live registry.
trait ArtifactFetcher {
    fn fetch(&self, artifact: &greentic_update::plan::PlanArtifact) -> Result<Vec<u8>, OpError>;
}

/// Retry/backoff for a transient artifact fetch: `attempts` total tries with
/// exponential backoff from `base_delay`. Tests use a zero delay.
#[derive(Clone, Copy)]
struct RetryPolicy {
    attempts: u32,
    base_delay: std::time::Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            attempts: 3,
            base_delay: std::time::Duration::from_millis(500),
        }
    }
}

/// The production [`ArtifactFetcher`]: resolves and fetches through the
/// content-addressed `DistClient` (handles `oci://`, `https://`, `file://`),
/// returning the cached bytes. It does not need to trust the transport —
/// artifacts are integrity-anchored by the signed plan's digests (`put_artifact`
/// re-verifies), not by mTLS. The plan document itself is the mTLS/DSSE-verified
/// artifact; its listed content is digest-verified regardless of how it arrives.
struct DistArtifactFetcher {
    client: DistClient,
}

impl DistArtifactFetcher {
    fn new() -> Self {
        Self {
            client: DistClient::new(DistOptions::default()),
        }
    }
}

impl ArtifactFetcher for DistArtifactFetcher {
    fn fetch(&self, artifact: &greentic_update::plan::PlanArtifact) -> Result<Vec<u8>, OpError> {
        let source = artifact.source.as_deref().ok_or_else(|| {
            OpError::InvalidArgument(format!(
                "artifact `{}` declares no source to download (in-band airgap \
                 artifacts are not supported by `op updates get`)",
                artifact.name
            ))
        })?;
        // Confine sources to remote registry schemes — an explicit `https://` or
        // `oci://`. Reject `file://`, bare local paths, and DistClient's other
        // schemes: even a signed plan must not make the operator read local
        // files or resolve ambiguous bare refs. Digest verification only happens
        // AFTER a fetch, so the scheme is the pre-fetch trust boundary.
        if !(source.starts_with("https://") || source.starts_with("oci://")) {
            return Err(OpError::InvalidArgument(format!(
                "artifact `{}` source `{source}` is not an allowed remote scheme \
                 (expected `https://` or `oci://`)",
                artifact.name
            )));
        }
        rt::sync_await(async {
            let parsed = self
                .client
                .parse_source(source)
                .map_err(|e| OpError::Fetch(format!("parse artifact source `{source}`: {e}")))?;
            let descriptor = self
                .client
                .resolve(parsed, ResolvePolicy)
                .await
                .map_err(|e| {
                    OpError::Fetch(format!("resolve artifact `{}`: {e}", artifact.name))
                })?;
            // Require a KNOWN, in-bounds size *before* fetching the body. The
            // resolver reports `size_bytes == 0` when the source declared no size
            // (e.g. a direct-HTTPS response with no `Content-Length`); fetching
            // such a source streams an unbounded body to disk before the
            // post-fetch length cap below can trip. Refuse it fail-closed rather
            // than download something we cannot bound up front.
            reject_unsized_or_oversize(artifact, descriptor.size_bytes)?;
            let resolved = self
                .client
                .fetch(&descriptor, CachePolicy)
                .await
                .map_err(|e| OpError::Fetch(format!("fetch artifact `{}`: {e}", artifact.name)))?;
            // Authoritative cap on the actual bytes before loading them into
            // memory (and into `put_artifact`'s digest buffer).
            let len = std::fs::metadata(&resolved.local_path)
                .map_err(|e| {
                    OpError::Fetch(format!(
                        "stat fetched artifact `{}` at {}: {e}",
                        artifact.name,
                        resolved.local_path.display()
                    ))
                })?
                .len();
            reject_oversize(artifact, len)?;
            std::fs::read(&resolved.local_path).map_err(|e| {
                OpError::Fetch(format!(
                    "read fetched artifact `{}` at {}: {e}",
                    artifact.name,
                    resolved.local_path.display()
                ))
            })
        })
    }
}

/// Hard ceiling on a single downloaded artifact — bounds the in-memory read and
/// the digest-check buffer (`put_artifact` takes the whole `&[u8]`). Update
/// artifacts (packs, wasm, binaries) are far smaller; this only trips on a
/// poisoned or oversized source, before the digest gate can reject it.
const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;

fn reject_oversize(
    artifact: &greentic_update::plan::PlanArtifact,
    size: u64,
) -> Result<(), OpError> {
    if size > MAX_ARTIFACT_BYTES {
        return Err(OpError::Fetch(format!(
            "artifact `{}` is {size} bytes, over the {MAX_ARTIFACT_BYTES}-byte cap",
            artifact.name
        )));
    }
    Ok(())
}

/// Pre-fetch size gate: the resolver-declared `size` must be both KNOWN
/// (non-zero) and within [`MAX_ARTIFACT_BYTES`]. A `size` of 0 means the source
/// declared no size, so the download could not be bounded before streaming it to
/// disk — refuse it fail-closed. (An empty artifact is degenerate anyway; a real
/// one would fail its digest gate.)
fn reject_unsized_or_oversize(
    artifact: &greentic_update::plan::PlanArtifact,
    size: u64,
) -> Result<(), OpError> {
    if size == 0 {
        return Err(OpError::Fetch(format!(
            "artifact `{}` has no declared size (the source sent no Content-Length); \
             refusing to fetch an unbounded body",
            artifact.name
        )));
    }
    reject_oversize(artifact, size)
}

/// Fetch one artifact, retrying transient failures with exponential backoff.
/// Every fetch error is treated as retryable — the authoritative integrity gate
/// is `put_artifact`'s digest check, not the fetch outcome.
fn fetch_with_retry(
    fetcher: &dyn ArtifactFetcher,
    artifact: &greentic_update::plan::PlanArtifact,
    retry: RetryPolicy,
) -> Result<Vec<u8>, OpError> {
    let attempts = retry.attempts.max(1);
    let mut delay = retry.base_delay;
    let mut last_err = None;
    for attempt in 1..=attempts {
        match fetcher.fetch(artifact) {
            Ok(bytes) => return Ok(bytes),
            Err(e) => {
                last_err = Some(e);
                if attempt < attempts {
                    if !delay.is_zero() {
                        std::thread::sleep(delay);
                    }
                    delay = delay.saturating_mul(2);
                }
            }
        }
    }
    Err(last_err.expect("retry loop runs at least once"))
}

/// Download every artifact a plan declares into its staging tree, then promote
/// `downloading → inbox → staged`. Idempotent/resumable: a plan already past
/// `downloading` (a completed prior run) is returned as-is without re-fetching;
/// while `downloading`, every artifact is (re-)fetched and handed to
/// `put_artifact`, which is content-addressed and fail-closed on a digest
/// mismatch — so re-fetching an already-present artifact is safe.
fn download_and_stage(
    staged: &greentic_update::staging::StagedPlan,
    artifacts: &[greentic_update::plan::PlanArtifact],
    fetcher: &dyn ArtifactFetcher,
    retry: RetryPolicy,
) -> Result<greentic_update::staging::UpdateStage, OpError> {
    use greentic_update::staging::UpdateStage;
    let stage = staged
        .stage()
        .map_err(|e| OpError::Conflict(format!("read update staging stage: {e}")))?;
    // Resume: only fetch while still `downloading`. A plan already promoted or
    // terminal has been handled — return its stage unchanged.
    if stage != UpdateStage::Downloading {
        return Ok(stage);
    }
    for artifact in artifacts {
        let bytes = fetch_with_retry(fetcher, artifact, retry)?;
        staged
            .put_artifact(artifact, &bytes)
            .map_err(|e| OpError::Conflict(format!("stage artifact `{}`: {e}", artifact.name)))?;
    }
    // Every artifact is present and digest-verified → promote to `staged`.
    advance_to_staged(staged)
}

/// Resolve the `(plan document, DSSE envelope)` byte pair from the payload's
/// source. Exactly one of `plan_url` or (`plan_file` + `plan_sig_file`) must be
/// set.
fn load_plan_source(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
    payload: &UpdatesGetPayload,
) -> Result<(Vec<u8>, Vec<u8>), OpError> {
    match (
        &payload.plan_url,
        &payload.plan_file,
        &payload.plan_sig_file,
    ) {
        (Some(url), None, None) => {
            // The plan is fetched over the enrolled mTLS identity, which is only
            // presented over TLS — reject plaintext `http://` (except loopback,
            // for a local dev server) so a remote endpoint can't be reached
            // without the client cert.
            if !control_url_is_acceptable(url) {
                return Err(OpError::InvalidArgument(
                    "plan_url must be an https:// URL; plaintext http:// is accepted only for a \
                     loopback dev server. The enrolled mTLS client identity is presented only over \
                     TLS, so a plaintext fetch would bypass it."
                        .to_string(),
                ));
            }
            fetch_plan_over_mtls(store, env, env_id, url)
        }
        (None, Some(plan), Some(sig)) => {
            let plan_bytes = std::fs::read(plan).map_err(|source| OpError::Io {
                path: plan.clone(),
                source,
            })?;
            let sig_bytes = std::fs::read(sig).map_err(|source| OpError::Io {
                path: sig.clone(),
                source,
            })?;
            Ok((plan_bytes, sig_bytes))
        }
        _ => Err(OpError::InvalidArgument(
            "exactly one plan source is required: `plan_url`, or `plan_file` with `plan_sig_file`"
                .to_string(),
        )),
    }
}

/// Fetch the plan document + `.sig` sidecar over the enrolled mTLS channel,
/// using the persisted cert/key/CA (from `enroll`). GETs `<plan_url>` for the
/// document and `<plan_url>.sig` for the envelope — the crate's sidecar
/// convention (`plan.json` + `plan.json.sig`). Integration-covered: no plan
/// server exists until Phase 6, so the local `plan_file` pair is the unit-tested
/// source.
fn fetch_plan_over_mtls(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
    plan_url: &str,
) -> Result<(Vec<u8>, Vec<u8>), OpError> {
    let secrets = require_secrets_pack(env, env_id)?;
    let kind_path = secrets.kind.path();
    let tenant = require_tenant(env, env_id)?;

    let identity = load_identity(store, env, env_id, kind_path, &tenant)?.ok_or_else(|| {
        OpError::NotFound(format!(
            "env `{env_id}` is not enrolled for updates; run `op updates enroll` first"
        ))
    })?;
    let StoredIdentity {
        client_key_pem: key_pem,
        client_cert_pem: cert_pem,
        ca_pem,
        ..
    } = identity;

    // Build the `.sig` sidecar URL by mutating the path (not appending to the
    // raw string), so a query/fragment on `plan_url` doesn't corrupt it.
    let sig_url = {
        let mut u = url::Url::parse(plan_url)
            .map_err(|e| OpError::InvalidArgument(format!("plan_url: {e}")))?;
        let sig_path = format!("{}.sig", u.path());
        u.set_path(&sig_path);
        u.to_string()
    };
    rt::sync_await(async {
        let client = greentic_update::tls::build_mtls_client(&greentic_update::tls::MtlsConfig {
            ca_pem,
            client_cert_pem: cert_pem,
            client_key_pem: key_pem,
        })
        .map_err(|e| OpError::Conflict(format!("stored mTLS identity is unusable: {e}")))?;
        let plan_bytes = mtls_get(&client, plan_url).await?;
        let sig_bytes = mtls_get(&client, &sig_url).await?;
        Ok::<(Vec<u8>, Vec<u8>), OpError>((plan_bytes, sig_bytes))
    })
}

/// GET `url` over the mTLS client, returning the body bytes. Non-2xx and
/// transport errors both map to [`OpError::Fetch`].
async fn mtls_get(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, OpError> {
    let resp = client
        .get(url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| OpError::Fetch(format!("GET {url}: {e}")))?;
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| OpError::Fetch(format!("GET {url}: reading body: {e}")))?;
    Ok(bytes.to_vec())
}

// ---------------------------------------------------------------------------
// plan-build: build + DSSE-sign an UpdatePlan carrying binary artifacts
// ---------------------------------------------------------------------------

/// Parse a `--binary` spec string (comma-separated key=value) into a
/// [`greentic_update::plan::BinaryArtifact`]. Required keys: `name`, `version`,
/// `target`, `digest`. Optional: `source`.
/// A `--binary` spec's required key must be present and non-empty.
fn require_non_empty(value: Option<String>, key: &str) -> Result<String, OpError> {
    let value = value.ok_or_else(|| {
        OpError::InvalidArgument(format!("--binary: missing required key `{key}`"))
    })?;
    if value.is_empty() {
        return Err(OpError::InvalidArgument(format!(
            "--binary: `{key}` must not be empty"
        )));
    }
    Ok(value)
}

fn parse_binary_spec(spec: &str) -> Result<greentic_update::plan::BinaryArtifact, OpError> {
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut target: Option<String> = None;
    let mut digest: Option<String> = None;
    let mut source: Option<String> = None;

    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = part.split_once('=').ok_or_else(|| {
            OpError::InvalidArgument(format!("--binary: expected key=value pair, got `{part}`"))
        })?;
        match key {
            "name" => {
                if name.is_some() {
                    return Err(OpError::InvalidArgument(
                        "--binary: duplicate key `name`".to_string(),
                    ));
                }
                name = Some(value.to_string());
            }
            "version" => {
                if version.is_some() {
                    return Err(OpError::InvalidArgument(
                        "--binary: duplicate key `version`".to_string(),
                    ));
                }
                version = Some(value.to_string());
            }
            "target" => {
                if target.is_some() {
                    return Err(OpError::InvalidArgument(
                        "--binary: duplicate key `target`".to_string(),
                    ));
                }
                target = Some(value.to_string());
            }
            "digest" => {
                if digest.is_some() {
                    return Err(OpError::InvalidArgument(
                        "--binary: duplicate key `digest`".to_string(),
                    ));
                }
                digest = Some(value.to_string());
            }
            "source" => {
                if source.is_some() {
                    return Err(OpError::InvalidArgument(
                        "--binary: duplicate key `source`".to_string(),
                    ));
                }
                source = Some(value.to_string());
            }
            unknown => {
                return Err(OpError::InvalidArgument(format!(
                    "--binary: unknown key `{unknown}` (expected name, version, target, digest, source)"
                )));
            }
        }
    }

    let name = require_non_empty(name, "name")?;
    let version = require_non_empty(version, "version")?;
    let target = require_non_empty(target, "target")?;
    let digest = require_non_empty(digest, "digest")?;

    Ok(greentic_update::plan::BinaryArtifact {
        name,
        version,
        target,
        digest,
        source,
    })
}

/// Parse the `owner/repo` form into `(owner, repo)`. Falls back to
/// `(greenticai, raw)` when no `/` is present.
fn parse_owner_repo(raw: &str) -> (String, String) {
    match raw.split_once('/') {
        Some((owner, repo)) => (owner.to_string(), repo.to_string()),
        None => ("greenticai".to_string(), raw.to_string()),
    }
}

/// Resolve `--release` into pre-derived `BinaryArtifact`s. Returns an empty
/// vec when `--release` is not set.
fn resolve_release_artifacts(
    release: Option<&str>,
    release_repo: Option<&str>,
    release_binary_name: Option<&str>,
    targets: &[String],
    expected_target_count: Option<usize>,
) -> Result<Vec<greentic_update::plan::BinaryArtifact>, OpError> {
    let version = match release {
        Some(v) => v,
        None => return Ok(vec![]),
    };
    let (owner, repo) = parse_owner_repo(release_repo.unwrap_or("greenticai/greentic-start"));
    let binary_name = release_binary_name.unwrap_or("greentic-start").to_string();
    let spec = super::release_artifacts::ReleaseSpec {
        owner,
        repo,
        binary_name,
        version: version.to_string(),
        tag: format!("v{version}"),
        targets: targets.to_vec(),
        expected_target_count,
    };
    super::release_artifacts::derive_binary_artifacts(&spec)
}

/// `op updates plan-build` — build and DSSE-sign an [`UpdatePlan`] carrying a
/// content target (`--target-file`), one or more binary artifacts (`--binary`),
/// or both, writing `plan.json` + `plan.json.sig` to the output directory. The
/// emitted pair round-trips through
/// [`greentic_update::plan::verify_update_plan`] against the env's trust root.
///
/// This is the producer side of the update path: `--target-file` drives the
/// content convergence `op updates apply` performs, `--binary` drives
/// `greentic-start`'s stage-only binary self-update. A plan with neither is a
/// signed no-op and is rejected.
pub fn plan_build(
    store: &LocalFsStore,
    flags: &OpFlags,
    args: crate::cli::dispatch::UpdatesPlanBuildArgs,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "plan-build", plan_build_schema()));
    }

    let env_id_raw = args.env_id.ok_or_else(|| {
        OpError::InvalidArgument("env_id is required (positional argument)".to_string())
    })?;
    let env_id = parse_env_id(&env_id_raw)?;

    let sequence = args
        .sequence
        .ok_or_else(|| OpError::InvalidArgument("--sequence is required".to_string()))?;

    let derived_binaries = resolve_release_artifacts(
        args.release.as_deref(),
        args.release_repo.as_deref(),
        args.release_binary_name.as_deref(),
        &args.targets,
        args.expected_target_count,
    )?;

    let signed = build_and_sign_plan(
        store,
        &env_id,
        sequence,
        &PlanContent {
            binaries: &args.binaries,
            derived_binaries,
            target_file: args.target_file.as_deref(),
            min_runtime: args.min_runtime,
            signing_key: args.signing_key.as_deref(),
            trust_root: args.trust_root.as_deref(),
        },
    )?;

    // Write plan.json + plan.json.sig to the output directory.
    let out_dir = args.out_dir.unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&out_dir).map_err(|source| OpError::Io {
        path: out_dir.clone(),
        source,
    })?;
    let plan_path = out_dir.join("plan.json");
    let sig_path = out_dir.join("plan.json.sig");
    std::fs::write(&plan_path, &signed.plan_bytes).map_err(|source| OpError::Io {
        path: plan_path.clone(),
        source,
    })?;
    std::fs::write(&sig_path, &signed.envelope_bytes).map_err(|source| OpError::Io {
        path: sig_path.clone(),
        source,
    })?;

    Ok(OpOutcome::new(
        NOUN,
        "plan-build",
        json!({
            "environment_id": env_id.as_str(),
            "plan_id": signed.plan_id,
            "sequence": signed.sequence,
            "plan_sha256": signed.plan_sha256,
            "key_id": signed.key_id,
            "plan_path": plan_path.display().to_string(),
            "sig_path": sig_path.display().to_string(),
            "stripped_updates_block": signed.stripped.updates,
            "stripped_trust_root": signed.stripped.trust_root,
        }),
    ))
}

/// What goes *into* a plan, as opposed to where the signed bytes go. Shared by
/// the offline producer (`plan-build` → files) and the online one
/// (`publish` → plan server).
struct PlanContent<'a> {
    binaries: &'a [String],
    /// Pre-derived artifacts (from --release). When non-empty, `binaries`
    /// (raw --binary specs) must be empty (enforced by clap conflicts_with).
    derived_binaries: Vec<greentic_update::plan::BinaryArtifact>,
    target_file: Option<&'a Path>,
    min_runtime: Option<String>,
    signing_key: Option<&'a Path>,
    /// Override for the trust root file path. When set, the trust root is
    /// loaded from this file instead of `<env_dir>/trust-root.json`.
    trust_root: Option<&'a Path>,
}

/// A built, DSSE-signed plan held in memory.
struct SignedPlan {
    plan_id: String,
    sequence: u64,
    plan_bytes: Vec<u8>,
    envelope_bytes: Vec<u8>,
    plan_sha256: String,
    key_id: String,
    /// Which non-applyable blocks were stripped from the target before signing.
    stripped: StrippedBlocks,
}

/// Remove blocks that [`check_applyable_manifest`] would reject from a plan
/// target, returning which ones were present. Stripped here at sign time;
/// `check_applyable_manifest` refuses them at apply time as the fail-closed
/// backstop for plans built any other way.
///
/// Currently strips:
/// - `updates` — the update channel is operator-local state; a plan that
///   re-points `plan_endpoint` controls every plan that follows it.
/// - `trust_root` — seeds or rotates the env's signing-key trust anchor; a
///   plan that re-points it gains permanent signing authority.
fn strip_non_applyable_blocks(target: &mut serde_json::Value) -> StrippedBlocks {
    let Some(obj) = target.as_object_mut() else {
        return StrippedBlocks {
            updates: false,
            trust_root: false,
        };
    };
    StrippedBlocks {
        updates: obj.remove("updates").is_some(),
        trust_root: obj.remove("trust_root").is_some(),
    }
}

/// Which non-applyable blocks were stripped from a plan target at sign time.
#[derive(Debug, Clone, Copy)]
struct StrippedBlocks {
    updates: bool,
    trust_root: bool,
}

/// Reject, before signing, a plan target the consumer is guaranteed to refuse.
///
/// `op updates apply` deserializes the signed target as an [`EnvManifest`] and
/// requires its environment id to match the plan's. Skipping those checks on the
/// producer side used to be harmless: `plan-build` writes to a directory, and an
/// operator inspects the pair before doing anything with it. `publish` uploads
/// straight to the live channel and consumes a sequence number, so a malformed or
/// misaddressed target would become the plan every client fetches, DSSE-verifies
/// and rejects, once per poll cycle, until a corrected plan is published at a
/// higher sequence. Fail here instead.
///
/// Deliberately *not* the full [`check_applyable_manifest`]: that also gates on
/// the target env's runtime state (its secrets sink, its rollback snapshot),
/// which the producer does not share with the consumer.
fn validate_plan_target(target: &serde_json::Value, env_id: &EnvId) -> Result<(), OpError> {
    let manifest: EnvManifest = serde_json::from_value(target.clone()).map_err(|e| {
        OpError::InvalidArgument(format!(
            "plan target is not a valid `{}`: {e}",
            super::env_manifest::ENV_MANIFEST_SCHEMA_V1
        ))
    })?;
    manifest.validate_shape()?;
    if manifest.environment.id != env_id.as_str() {
        return Err(OpError::InvalidArgument(format!(
            "plan target declares environment `{}`, but the plan is for `{env_id}`",
            manifest.environment.id
        )));
    }
    Ok(())
}

/// Load a trust root from an explicit file path (vs the directory-based
/// [`store_trust_root::load`]).
fn load_trust_root_from_file(
    path: &Path,
) -> Result<greentic_distributor_client::signing::TrustRoot, OpError> {
    use greentic_operator_trust::trust_root::TrustRootDocument;
    let bytes = std::fs::read(path).map_err(|source| OpError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let doc: TrustRootDocument = serde_json::from_slice(&bytes)
        .map_err(|e| OpError::InvalidArgument(format!("trust root {}: {e}", path.display())))?;
    doc.into_trust_root()
        .map_err(|e| OpError::InvalidArgument(format!("trust root {}: {e}", path.display())))
}

/// Build + DSSE-sign an [`UpdatePlan`](greentic_update::plan::UpdatePlan) for
/// `env_id` against the env's trust root. The signed pair round-trips through
/// [`greentic_update::plan::verify_update_plan`].
///
/// A plan with neither a content target nor a binary artifact converges nothing:
/// `op updates apply` is upsert-only, so the default minimal target is a no-op,
/// and there is no binary for the runtime to swap. Refuse to sign it rather than
/// mint a plan that reports `applied` without changing anything.
fn build_and_sign_plan(
    store: &LocalFsStore,
    env_id: &EnvId,
    sequence: u64,
    content: &PlanContent<'_>,
) -> Result<SignedPlan, OpError> {
    use chrono::Utc;
    use greentic_update::plan::{
        BinaryArtifact, CompatRequirements, OnFail, RollbackKind, RollbackPolicy,
        UPDATE_PLAN_SCHEMA_V1, UpdatePlan,
    };

    // Resolve binary artifacts: pre-derived (--release) or parsed (--binary).
    let binaries: Vec<BinaryArtifact> = if !content.derived_binaries.is_empty() {
        content.derived_binaries.clone()
    } else {
        content
            .binaries
            .iter()
            .map(|s| parse_binary_spec(s))
            .collect::<Result<Vec<_>, _>>()?
    };

    if binaries.is_empty() && content.target_file.is_none() {
        return Err(OpError::InvalidArgument(
            "at least one --binary or a --target-file is required".to_string(),
        ));
    }

    // Resolve the signing key: explicit --signing-key or the global operator key.
    let (priv_pem, key_id) = match content.signing_key {
        Some(key_path) => crate::operator_key::read_signing_key_at(key_path)?,
        None => {
            let op_key = crate::operator_key::load_existing_only().map_err(|e| {
                OpError::InvalidArgument(format!(
                    "no --signing-key provided and the global operator key is unavailable: {e}. \
                     Create or bootstrap the operator key first, or pass --signing-key <path>."
                ))
            })?;
            (op_key.private_pem, op_key.key_id)
        }
    };

    // Load the env trust root so build_update_plan can verify the key is trusted.
    let trust = match content.trust_root {
        Some(path) => load_trust_root_from_file(path)?,
        None => {
            let env_dir = store.env_dir(env_id)?;
            store_trust_root::load(&env_dir)?
        }
    };

    // Build the plan target from --target-file or a minimal valid env-manifest.
    let mut target: serde_json::Value = match content.target_file {
        Some(path) => {
            let bytes = std::fs::read(path).map_err(|source| OpError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            serde_json::from_slice(&bytes).map_err(|e| {
                OpError::InvalidArgument(format!(
                    "target file {} is not valid JSON: {e}",
                    path.display()
                ))
            })?
        }
        None => json!({
            "schema": super::env_manifest::ENV_MANIFEST_SCHEMA_V1,
            "environment": { "id": env_id.as_str() },
        }),
    };
    let stripped = strip_non_applyable_blocks(&mut target);
    // Validate the document we are about to sign — i.e. after the strip.
    validate_plan_target(&target, env_id)?;

    let mut compat = CompatRequirements::default();
    if let Some(min_rt) = content.min_runtime.clone() {
        compat.min_runtime = Some(min_rt);
    }

    let plan = UpdatePlan {
        schema: UPDATE_PLAN_SCHEMA_V1.to_string(),
        plan_id: ulid::Ulid::new().to_string(),
        env_id: env_id.to_string(),
        sequence,
        created_at: Utc::now(),
        nonce: ulid::Ulid::new().to_string(),
        target,
        artifacts: vec![],
        binaries,
        compat,
        rollback: RollbackPolicy {
            policy: RollbackKind::Auto,
            health_timeout_s: 120,
            on_fail: OnFail::Restore,
        },
    };

    let built = greentic_update::plan::build_update_plan(&plan, &priv_pem, &key_id, &trust)
        .map_err(|e| {
            OpError::Conflict(format!(
                "build + sign update plan failed (is the signing key trusted by the env \
                 trust root?): {e}"
            ))
        })?;

    Ok(SignedPlan {
        plan_id: plan.plan_id,
        sequence: plan.sequence,
        plan_bytes: built.plan_bytes,
        envelope_bytes: built.envelope_bytes,
        plan_sha256: built.plan_sha256,
        key_id: built.key_id,
        stripped,
    })
}

fn plan_build_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "UpdatesPlanBuildArgs",
        "type": "object",
        "required": ["env_id", "sequence"],
        "additionalProperties": false,
        "anyOf": [
            {"required": ["binaries"]},
            {"required": ["target_file"]},
            {"required": ["release"]}
        ],
        "properties": {
            "env_id": {"type": "string"},
            "sequence": {"type": "integer", "description": "Monotonic plan sequence (anti-rollback)."},
            "binaries": {"type": "array", "items": {"type": "string"}, "description": "Binary artifact specs (comma-separated key=value). Required unless target_file or release is set."},
            "signing_key": {"type": ["string", "null"], "description": "PKCS#8 Ed25519 private key PEM path. Default: global operator key."},
            "target_file": {"type": ["string", "null"], "description": "JSON file for the plan target (env-manifest.v1). Required unless binaries or release is set. Default: minimal manifest with schema + env id."},
            "min_runtime": {"type": ["string", "null"], "description": "Minimum runtime version (semver) for compat.min_runtime."},
            "out_dir": {"type": ["string", "null"], "description": "Output directory for plan.json + plan.json.sig. Default: current dir."},
            "release": {"type": ["string", "null"], "description": "Derive binary artifacts from a GitHub release version (e.g. 1.1.12). Conflicts with binaries."},
            "release_repo": {"type": ["string", "null"], "description": "GitHub owner/repo for --release. Default: greenticai/greentic-start."},
            "release_binary_name": {"type": ["string", "null"], "description": "Binary name inside the archive for --release. Default: greentic-start."},
            "targets": {"type": "array", "items": {"type": "string"}, "description": "Target triples to derive from the release. Default: all."},
            "trust_root": {"type": ["string", "null"], "description": "Path to a trust-root.json file. Bypasses env-store lookup."}
        }
    })
}

// ---------------------------------------------------------------------------
// publish: sign a plan and upload it to the environment's plan server
// ---------------------------------------------------------------------------

/// Env var consulted for the plan-server upload credential when
/// `--upload-token` is not supplied. Preferred over the flag: a token on the
/// command line lands in shell history and `ps`.
const UPLOAD_TOKEN_ENV: &str = "GREENTIC_PLAN_UPLOAD_TOKEN";

/// Advisory metadata the plan server serves at `{plan_endpoint}/meta`.
#[derive(Deserialize)]
struct PlanMeta {
    sequence: u64,
}

/// `op updates publish <env> --target-file <manifest.json>` — sign the target
/// and upload it to the environment's plan server, in one step.
///
/// The online counterpart to [`plan_build`]: same signing core, but the sequence
/// comes from the server and the bytes go to the server rather than to disk.
///
/// **Sequence.** `--sequence` is optional. Unset, it is `{plan_endpoint}/meta`'s
/// current sequence plus one (`1` if the server has no plan yet). The operator's
/// own machine is the wrong source: in production it holds no applied-set to
/// count from, and the server enforces strict monotonicity anyway — a concurrent
/// publisher loses with a `409` rather than silently forking the channel.
///
/// **Endpoint.** Defaults to the env's configured `plan_endpoint`, so the
/// environment's own subscription decides where its updates are published.
///
/// This is the *only* verb that talks to the plan server. It uploads bytes; it
/// never asks the server to sign anything, and the signing key never leaves this
/// machine.
pub fn publish(
    store: &LocalFsStore,
    flags: &OpFlags,
    args: crate::cli::dispatch::UpdatesPublishArgs,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "publish", publish_schema()));
    }

    let derived_binaries = resolve_release_artifacts(
        args.release.as_deref(),
        args.release_repo.as_deref(),
        args.release_binary_name.as_deref(),
        &args.targets,
        args.expected_target_count,
    )?;

    let token = args
        .upload_token
        .or_else(|| std::env::var(UPLOAD_TOKEN_ENV).ok())
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            OpError::InvalidArgument(format!(
                "no plan-server upload credential: set ${UPLOAD_TOKEN_ENV} or pass --upload-token"
            ))
        })?;

    if args.target_file.is_none() && args.binaries.is_empty() && derived_binaries.is_empty() {
        return Err(OpError::InvalidArgument(
            "--target-file, --binary, or --release is required".to_string(),
        ));
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| OpError::Fetch(format!("building HTTP client: {e}")))?;

    if args.all_envs {
        return publish_all_envs(
            store,
            &client,
            &token,
            &args.binaries,
            derived_binaries,
            args.target_file.as_deref(),
            args.min_runtime,
            args.signing_key.as_deref(),
            args.trust_root.as_deref(),
            args.plan_server_url
                .as_deref()
                .expect("clap requires plan_server_url with all_envs"),
            args.sequence,
        );
    }

    let env_id_raw = args.env_id.ok_or_else(|| {
        OpError::InvalidArgument("env_id is required (positional argument)".to_string())
    })?;
    let env_id = parse_env_id(&env_id_raw)?;

    // Resolve every input before signing, so a missing token or endpoint fails
    // without minting a plan and burning a sequence number.
    let plan_endpoint = match args.plan_endpoint {
        Some(raw) => raw,
        None => match &args.plan_server_url {
            Some(base) => format!(
                "{}/v1/environments/{}/plan",
                base.trim_end_matches('/'),
                env_id.as_str()
            ),
            None => store
                .load_update_channel(&env_id)?
                .and_then(|cfg| cfg.resolved_plan_endpoint().map(str::to_string))
                .ok_or_else(|| {
                    OpError::InvalidArgument(format!(
                        "env `{env_id}` has no configured plan_endpoint; declare an `updates` \
                         block in its manifest, run `op updates config-set --plan-endpoint \
                         <url>`, or pass --plan-endpoint"
                    ))
                })?,
        },
    };
    let plan_endpoint = plan_endpoint.trim().trim_end_matches('/').to_string();
    if !control_url_is_acceptable(&plan_endpoint) {
        return Err(OpError::InvalidArgument(format!(
            "plan_endpoint {plan_endpoint:?} is not an acceptable control URL \
             (https required; http only to loopback)"
        )));
    }

    let sequence = match args.sequence {
        Some(explicit) => explicit,
        None => rt::sync_await(next_sequence(&client, &plan_endpoint))?,
    };

    let signed = build_and_sign_plan(
        store,
        &env_id,
        sequence,
        &PlanContent {
            binaries: &args.binaries,
            derived_binaries,
            target_file: args.target_file.as_deref(),
            min_runtime: args.min_runtime,
            signing_key: args.signing_key.as_deref(),
            trust_root: args.trust_root.as_deref(),
        },
    )?;

    rt::sync_await(upload_plan(&client, &plan_endpoint, &token, &signed))?;

    Ok(OpOutcome::new(
        NOUN,
        "publish",
        json!({
            "environment_id": env_id.as_str(),
            "plan_id": signed.plan_id,
            "sequence": signed.sequence,
            "plan_sha256": signed.plan_sha256,
            "key_id": signed.key_id,
            "plan_endpoint": plan_endpoint,
            "status": "published",
            "stripped_updates_block": signed.stripped.updates,
            "stripped_trust_root": signed.stripped.trust_root,
        }),
    ))
}

/// Environment record returned by `GET /v1/environments`.
#[derive(Debug, Deserialize)]
struct EnvironmentRecord {
    id: String,
}

/// `--all-envs` publish: enumerate environments from the plan server, then
/// sign + upload one plan per env. Returns a summary with per-env
/// results; exits non-zero (via `OpError::Conflict`) if any env failed.
#[allow(clippy::too_many_arguments)]
fn publish_all_envs(
    store: &LocalFsStore,
    client: &reqwest::Client,
    token: &str,
    binaries: &[String],
    derived_binaries: Vec<greentic_update::plan::BinaryArtifact>,
    target_file: Option<&Path>,
    min_runtime: Option<String>,
    signing_key: Option<&Path>,
    trust_root: Option<&Path>,
    plan_server_url: &str,
    explicit_sequence: Option<u64>,
) -> Result<OpOutcome, OpError> {
    let base = plan_server_url.trim_end_matches('/');
    if !control_url_is_acceptable(base) {
        return Err(OpError::InvalidArgument(format!(
            "plan_server_url {base:?} is not an acceptable control URL \
             (https required; http only to loopback)"
        )));
    }

    let envs_url = format!("{base}/v1/environments");
    let envs: Vec<EnvironmentRecord> = rt::sync_await(async {
        let resp = client
            .get(&envs_url)
            .header("x-api-key", token)
            .send()
            .await
            .map_err(|e| OpError::Fetch(format!("GET {envs_url}: {e}")))?;
        let resp = resp
            .error_for_status()
            .map_err(|e| OpError::Fetch(format!("GET {envs_url}: {e}")))?;
        resp.json::<Vec<EnvironmentRecord>>()
            .await
            .map_err(|e| OpError::Fetch(format!("GET {envs_url}: decode: {e}")))
    })?;

    if envs.is_empty() {
        return Err(OpError::NotFound(
            "plan server returned no registered environments".to_string(),
        ));
    }

    let mut published = Vec::new();
    let mut failed = Vec::new();

    for env_rec in &envs {
        let env_id = match parse_env_id(&env_rec.id) {
            Ok(id) => id,
            Err(e) => {
                failed.push(json!({"env_id": env_rec.id, "error": e.to_string()}));
                continue;
            }
        };
        let plan_endpoint = format!("{base}/v1/environments/{}/plan", env_id.as_str());

        let sequence = match explicit_sequence {
            Some(s) => s,
            None => match rt::sync_await(next_sequence(client, &plan_endpoint)) {
                Ok(s) => s,
                Err(e) => {
                    failed.push(json!({"env_id": env_id.as_str(), "error": e.to_string()}));
                    continue;
                }
            },
        };

        let signed = match build_and_sign_plan(
            store,
            &env_id,
            sequence,
            &PlanContent {
                binaries,
                derived_binaries: derived_binaries.clone(),
                target_file,
                min_runtime: min_runtime.clone(),
                signing_key,
                trust_root,
            },
        ) {
            Ok(s) => s,
            Err(e) => {
                failed.push(json!({"env_id": env_id.as_str(), "error": e.to_string()}));
                continue;
            }
        };

        if let Err(e) = rt::sync_await(upload_plan(client, &plan_endpoint, token, &signed)) {
            failed.push(json!({"env_id": env_id.as_str(), "error": e.to_string()}));
            continue;
        }

        published.push(json!({
            "env_id": env_id.as_str(),
            "plan_id": signed.plan_id,
            "sequence": signed.sequence,
            "plan_sha256": signed.plan_sha256,
        }));
    }

    let any_failed = !failed.is_empty();
    let outcome = OpOutcome::new(
        NOUN,
        "publish",
        json!({
            "status": if any_failed { "partial" } else { "published" },
            "plan_server_url": plan_server_url,
            "published": published,
            "failed": failed,
        }),
    );

    if any_failed {
        // Emit the structured per-env outcome to stdout so the operator can
        // see which environments succeeded and which failed, then return an
        // error so the exit code is non-zero.
        if let Ok(json) = serde_json::to_value(&outcome) {
            println!("{json}");
        }
        return Err(OpError::Conflict(format!(
            "{} of {} environments failed",
            failed.len(),
            envs.len()
        )));
    }

    Ok(outcome)
}

/// The sequence to publish next: one past whatever the server currently serves.
/// A `404` means the env has no plan yet (or is not registered), so the first
/// plan is sequence `1`.
async fn next_sequence(client: &reqwest::Client, plan_endpoint: &str) -> Result<u64, OpError> {
    let url = format!("{plan_endpoint}/meta");
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| OpError::Fetch(format!("GET {url}: {e}")))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(1);
    }
    let resp = resp
        .error_for_status()
        .map_err(|e| OpError::Fetch(format!("GET {url}: {e}")))?;
    let meta: PlanMeta = resp
        .json()
        .await
        .map_err(|e| OpError::Fetch(format!("GET {url}: decoding plan meta: {e}")))?;
    meta.sequence.checked_add(1).ok_or_else(|| {
        OpError::Conflict(format!(
            "plan sequence at {} is exhausted",
            meta.sequence // u64::MAX; a fresh env id is the only way forward
        ))
    })
}

/// POST the signed pair to the plan server. The plan and envelope travel
/// base64-encoded, not as nested JSON: DSSE pins `sha256(plan_bytes)` as the
/// subject digest, so re-serializing the plan would break verification.
async fn upload_plan(
    client: &reqwest::Client,
    plan_endpoint: &str,
    token: &str,
    signed: &SignedPlan,
) -> Result<(), OpError> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;

    let resp = client
        .post(plan_endpoint)
        .header("x-api-key", token)
        .json(&json!({
            "plan_bytes_b64": b64.encode(&signed.plan_bytes),
            "envelope_bytes_b64": b64.encode(&signed.envelope_bytes),
            "sequence": signed.sequence,
            "plan_sha256": signed.plan_sha256,
        }))
        .send()
        .await
        .map_err(|e| OpError::Fetch(format!("POST {plan_endpoint}: {e}")))?;

    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    // The server's message is the useful part (stale sequence, bad credential),
    // and it is our own control plane, so surface it rather than a bare code.
    let body = resp.text().await.unwrap_or_default();
    let detail = body.trim();
    let detail = if detail.is_empty() {
        "(no body)"
    } else {
        detail
    };
    Err(match status {
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
            OpError::Unauthorized {
                policy: "plan-server-upload".to_string(),
                reason: format!(
                    "plan server rejected the upload credential (is ${UPLOAD_TOKEN_ENV} the \
                     server's PLAN_UPLOAD_TOKEN?): {detail}"
                ),
            }
        }
        reqwest::StatusCode::CONFLICT => OpError::Conflict(format!(
            "plan server refused sequence {}: {detail}",
            signed.sequence
        )),
        _ => OpError::Fetch(format!("POST {plan_endpoint}: HTTP {status}: {detail}")),
    })
}

fn publish_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "UpdatesPublishArgs",
        "type": "object",
        "additionalProperties": false,
        "anyOf": [
            {"required": ["binaries"]},
            {"required": ["target_file"]},
            {"required": ["release"]}
        ],
        "properties": {
            "env_id": {"type": ["string", "null"], "description": "Target environment id. Required unless --all-envs is set."},
            "target_file": {"type": ["string", "null"], "description": "JSON file for the plan target (env-manifest.v1). Its `updates` block, if any, is stripped before signing. Required unless binaries or release is set."},
            "sequence": {"type": ["integer", "null"], "description": "Monotonic plan sequence (anti-rollback). Default: the server's current sequence + 1."},
            "binaries": {"type": "array", "items": {"type": "string"}, "description": "Binary artifact specs (comma-separated key=value). Conflicts with release."},
            "signing_key": {"type": ["string", "null"], "description": "PKCS#8 Ed25519 private key PEM path. Default: global operator key."},
            "min_runtime": {"type": ["string", "null"], "description": "Minimum runtime version (semver) for compat.min_runtime."},
            "plan_endpoint": {"type": ["string", "null"], "description": "Plan-server endpoint to publish to. Default: the env's configured plan_endpoint. Conflicts with plan_server_url."},
            "upload_token": {"type": ["string", "null"], "description": "Plan-server upload credential. Prefer $GREENTIC_PLAN_UPLOAD_TOKEN — a token on the command line lands in shell history."},
            "release": {"type": ["string", "null"], "description": "Derive binary artifacts from a GitHub release version (e.g. 1.1.12). Conflicts with binaries."},
            "release_repo": {"type": ["string", "null"], "description": "GitHub owner/repo for --release. Default: greenticai/greentic-start."},
            "release_binary_name": {"type": ["string", "null"], "description": "Binary name inside the archive for --release. Default: greentic-start."},
            "targets": {"type": "array", "items": {"type": "string"}, "description": "Target triples to derive from the release. Default: all."},
            "trust_root": {"type": ["string", "null"], "description": "Path to a trust-root.json file. Bypasses env-store lookup."},
            "all_envs": {"type": "boolean", "description": "Publish to ALL environments registered on the plan server. Requires plan_server_url."},
            "plan_server_url": {"type": ["string", "null"], "description": "Base URL of the plan server. Used with all_envs to enumerate environments."}
        }
    })
}

fn parse_env_id(raw: &str) -> Result<EnvId, OpError> {
    EnvId::try_from(raw).map_err(|e| OpError::InvalidArgument(format!("environment_id: {e}")))
}

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

fn enroll_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "UpdatesEnrollPayload",
        "type": "object",
        "required": ["environment_id", "ca_url"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "ca_url": {"type": "string", "description": "Base URL of the Cert-CA (greentic-updates-server); `/v1/enroll` is appended."}
        }
    })
}

fn status_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "UpdatesStatusPayload",
        "type": "object",
        "required": ["environment_id"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"}
        }
    })
}

fn get_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "UpdatesGetPayload",
        "type": "object",
        "required": ["environment_id"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "plan_url": {"type": "string", "description": "Fetch the signed plan (+ `.sig` sidecar) from this URL over the enrolled mTLS channel."},
            "plan_file": {"type": "string", "description": "Local plan document (airgap import / testing); requires plan_sig_file."},
            "plan_sig_file": {"type": "string", "description": "DSSE envelope sidecar for plan_file."}
        }
    })
}

fn apply_updates_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "ApplyUpdatesPayload",
        "type": "object",
        "required": ["environment_id", "plan_id"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "plan_id": {"type": "string", "description": "Plan id of the staged plan to apply (from `op updates get`)."}
        }
    })
}

fn recover_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "RecoverUpdatesPayload",
        "type": "object",
        "required": ["environment_id", "plan_id"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "plan_id": {"type": "string", "description": "Plan id of the `applying` plan to force-fail (from `op updates get`). Pass `--force` on the CLI to attest the applier is dead — recover refuses without it."}
        }
    })
}

fn config_set_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "UpdateConfigSetPayload",
        "type": "object",
        "required": ["environment_id"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "enabled": {"type": ["boolean", "null"], "description": "master switch for the update-channel notification machinery; null leaves the stored value unchanged (absent = disabled, deny-by-default)"},
            "on_notify": {"type": ["string", "null"], "enum": [null, "record-only", "record_only", "stage", "apply"], "description": "action on a verified plan; null leaves the stored value unchanged (unset resolves to `stage`). `apply` opts the environment into converging on its own; the executor lives in the runtime, and a greentic-start that predates `on_update` reads the legacy `on_notify: stage` mirror this also writes, staging instead of breaking"},
            "poll_interval_secs": {"type": ["integer", "null"], "minimum": MIN_POLL_INTERVAL_SECS, "description": "fallback poll interval in seconds; null leaves the stored value unchanged (unset resolves to 3600)"},
            "plan_endpoint": {"type": ["string", "null"], "description": "base URL to poll for the latest signed update plan (`{url}` + `{url}.sig`); null leaves the stored value unchanged; must be https (or http to loopback)"},
            "push_enabled": {"type": ["boolean", "null"], "description": "whether the runtime subscribes to a pushed update stream (SSE); null leaves the stored value unchanged (unset resolves to true)"},
            "stream_endpoint": {"type": ["string", "null"], "description": "SSE stream endpoint URL; null leaves the stored value unchanged (unset derives from plan_endpoint); must be https (or http to loopback)"}
        }
    })
}

fn config_show_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "UpdateConfigShowFilter",
        "type": "object",
        "required": ["environment_id"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"}
        }
    })
}

// Test-only fault-injection hook: called immediately before the
// `applying -> applied` transition retry loop in `apply_updates_impl`.
// Tests install a closure here to sabotage the on-disk plan directory
// (e.g. chmod it read-only) so the transition write fails, exercising the
// Case-B honest-error branch.
#[cfg(test)]
thread_local! {
    static PRE_APPLIED_TRANSITION_HOOK: std::cell::RefCell<Option<Box<dyn Fn()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_pre_applied_transition_hook() {
    PRE_APPLIED_TRANSITION_HOOK.with(|h| {
        if let Some(f) = h.borrow().as_ref() {
            f();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::secrets::{DEV_STORE_KIND_PATH, put_env_secret};
    use crate::cli::tests_common::{make_binding, make_env};
    use greentic_deploy_spec::{CapabilitySlot, OnNotifyAction};
    use tempfile::tempdir;

    // --- update-channel config (Phase 4 notification policy) ----------------

    fn store_with_env(dir: &std::path::Path, env_id: &str) -> (LocalFsStore, EnvId) {
        let store = LocalFsStore::new(dir);
        store.save(&make_env(env_id)).unwrap();
        (store, EnvId::try_from(env_id).unwrap())
    }

    #[test]
    fn config_show_defaults_to_disabled() {
        let dir = tempdir().unwrap();
        let (store, env_id) = store_with_env(dir.path(), "local");
        let out = config_show(
            &store,
            &OpFlags::default(),
            Some(UpdateConfigShowFilter {
                environment_id: "local".into(),
            }),
        )
        .unwrap();
        let resolved = &out.result["resolved"];
        assert_eq!(resolved["enabled"].as_bool(), Some(false));
        assert_eq!(resolved["on_notify"].as_str(), Some("stage"));
        assert_eq!(resolved["poll_interval_secs"].as_u64(), Some(3600));
        // A show never writes the sidecar.
        assert!(store.load_update_channel(&env_id).unwrap().is_none());
    }

    #[test]
    fn config_set_persists_and_round_trips() {
        let dir = tempdir().unwrap();
        let (store, env_id) = store_with_env(dir.path(), "local");
        config_set(
            &store,
            &OpFlags::default(),
            Some(UpdateConfigSetPayload {
                environment_id: "local".into(),
                enabled: Some(true),
                on_notify: Some("record-only".into()),
                poll_interval_secs: Some(120),
                plan_endpoint: Some("https://updates.example.com/plans/latest".into()),
                push_enabled: Some(false),
                stream_endpoint: Some("https://updates.example.com/updates/stream".into()),
            }),
        )
        .unwrap();
        let cfg = store.load_update_channel(&env_id).unwrap().unwrap();
        assert_eq!(cfg.enabled, Some(true));
        assert_eq!(cfg.on_notify, Some(OnNotifyAction::RecordOnly));
        assert_eq!(cfg.on_update, Some(UpdateAction::RecordOnly));
        assert_eq!(cfg.poll_interval_secs, Some(120));
        assert_eq!(
            cfg.plan_endpoint.as_deref(),
            Some("https://updates.example.com/plans/latest")
        );
        assert_eq!(cfg.push_enabled, Some(false));
        assert_eq!(
            cfg.stream_endpoint.as_deref(),
            Some("https://updates.example.com/updates/stream")
        );
        assert!(cfg.resolved_enabled());
        // Read back via config-show and verify the resolved view.
        let out = config_show(
            &store,
            &OpFlags::default(),
            Some(UpdateConfigShowFilter {
                environment_id: "local".into(),
            }),
        )
        .unwrap();
        assert_eq!(
            out.result["plan_endpoint"].as_str(),
            Some("https://updates.example.com/plans/latest")
        );
        assert_eq!(
            out.result["resolved"]["plan_endpoint"].as_str(),
            Some("https://updates.example.com/plans/latest")
        );
        assert_eq!(out.result["push_enabled"], false);
        assert_eq!(
            out.result["stream_endpoint"].as_str(),
            Some("https://updates.example.com/updates/stream")
        );
        assert_eq!(
            out.result["resolved"]["stream_endpoint"].as_str(),
            Some("https://updates.example.com/updates/stream")
        );
    }

    #[test]
    fn config_set_apply_persists_action_and_a_safe_legacy_mirror() {
        let dir = tempdir().unwrap();
        let (store, env_id) = store_with_env(dir.path(), "local");
        let out = config_set(
            &store,
            &OpFlags::default(),
            Some(UpdateConfigSetPayload {
                environment_id: "local".into(),
                enabled: Some(true),
                on_notify: Some("apply".into()),
                poll_interval_secs: None,
                plan_endpoint: None,
                push_enabled: None,
                stream_endpoint: None,
            }),
        )
        .unwrap();

        let cfg = store.load_update_channel(&env_id).unwrap().unwrap();
        assert_eq!(cfg.on_update, Some(UpdateAction::Apply));
        assert_eq!(cfg.resolved_action(), UpdateAction::Apply);
        // The whole point of the two-field shape: a binary that predates
        // `on_update` reads this and STAGES, rather than failing to parse the
        // channel or ignoring an operator's opt-in.
        assert_eq!(cfg.on_notify, Some(OnNotifyAction::Stage));

        assert_eq!(out.result["on_update"].as_str(), Some("apply"));
        assert_eq!(out.result["on_notify"].as_str(), Some("stage"));
        assert_eq!(out.result["resolved"]["action"].as_str(), Some("apply"));
    }

    #[test]
    fn config_set_partial_update_preserves_other_fields() {
        let dir = tempdir().unwrap();
        let (store, env_id) = store_with_env(dir.path(), "local");
        let set = |p: UpdateConfigSetPayload| {
            config_set(&store, &OpFlags::default(), Some(p)).unwrap();
        };
        set(UpdateConfigSetPayload {
            environment_id: "local".into(),
            enabled: Some(true),
            on_notify: None,
            poll_interval_secs: None,
            plan_endpoint: None,
            push_enabled: Some(false),
            stream_endpoint: Some("https://example.com/stream".into()),
        });
        set(UpdateConfigSetPayload {
            environment_id: "local".into(),
            enabled: None,
            on_notify: Some("record-only".into()),
            poll_interval_secs: None,
            plan_endpoint: None,
            push_enabled: None,
            stream_endpoint: None,
        });
        let cfg = store.load_update_channel(&env_id).unwrap().unwrap();
        assert_eq!(cfg.enabled, Some(true)); // preserved across the second set
        assert_eq!(cfg.on_notify, Some(OnNotifyAction::RecordOnly));
        assert_eq!(cfg.push_enabled, Some(false)); // preserved
        assert_eq!(
            cfg.stream_endpoint.as_deref(),
            Some("https://example.com/stream")
        ); // preserved
    }

    #[test]
    fn config_set_rejects_invalid_on_notify() {
        let dir = tempdir().unwrap();
        let (store, env_id) = store_with_env(dir.path(), "local");
        // `apply` used to be the example of an unsupported action; it is now a
        // real one, so the rejection is exercised with a value that is still not.
        let err = config_set(
            &store,
            &OpFlags::default(),
            Some(UpdateConfigSetPayload {
                environment_id: "local".into(),
                enabled: None,
                on_notify: Some("converge".into()),
                poll_interval_secs: None,
                plan_endpoint: None,
                push_enabled: None,
                stream_endpoint: None,
            }),
        )
        .unwrap_err();
        assert!(
            matches!(err, OpError::InvalidArgument(ref m) if m.contains("apply")),
            "got {err:?}"
        );
        // Fail-closed: nothing was written.
        assert!(store.load_update_channel(&env_id).unwrap().is_none());
    }

    #[test]
    fn config_set_rejects_poll_interval_below_floor() {
        let dir = tempdir().unwrap();
        let (store, _) = store_with_env(dir.path(), "local");
        let err = config_set(
            &store,
            &OpFlags::default(),
            Some(UpdateConfigSetPayload {
                environment_id: "local".into(),
                enabled: None,
                on_notify: None,
                poll_interval_secs: Some(10),
                plan_endpoint: None,
                push_enabled: None,
                stream_endpoint: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
    }

    #[test]
    fn config_set_rejects_unacceptable_plan_endpoint() {
        let dir = tempdir().unwrap();
        let (store, env_id) = store_with_env(dir.path(), "local");
        let err = config_set(
            &store,
            &OpFlags::default(),
            Some(UpdateConfigSetPayload {
                environment_id: "local".into(),
                enabled: None,
                on_notify: None,
                poll_interval_secs: None,
                plan_endpoint: Some("http://example.com/plan".into()),
                push_enabled: None,
                stream_endpoint: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
        // Fail-closed: nothing was written.
        assert!(store.load_update_channel(&env_id).unwrap().is_none());
    }

    #[test]
    fn config_set_rejects_blank_plan_endpoint() {
        let dir = tempdir().unwrap();
        let (store, env_id) = store_with_env(dir.path(), "local");

        // Whitespace-only is rejected.
        let err = config_set(
            &store,
            &OpFlags::default(),
            Some(UpdateConfigSetPayload {
                environment_id: "local".into(),
                enabled: None,
                on_notify: None,
                poll_interval_secs: None,
                plan_endpoint: Some("   ".into()),
                push_enabled: None,
                stream_endpoint: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
        let msg = format!("{err}");
        assert!(msg.contains("blank"), "error should mention 'blank': {msg}");
        // Fail-closed: nothing was written.
        assert!(store.load_update_channel(&env_id).unwrap().is_none());

        // Empty string is rejected the same way.
        let err2 = config_set(
            &store,
            &OpFlags::default(),
            Some(UpdateConfigSetPayload {
                environment_id: "local".into(),
                enabled: None,
                on_notify: None,
                poll_interval_secs: None,
                plan_endpoint: Some("".into()),
                push_enabled: None,
                stream_endpoint: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err2, OpError::InvalidArgument(_)), "got {err2:?}");
        let msg2 = format!("{err2}");
        assert!(
            msg2.contains("blank"),
            "error should mention 'blank': {msg2}"
        );
        assert!(store.load_update_channel(&env_id).unwrap().is_none());
    }

    #[test]
    fn config_set_rejects_unacceptable_stream_endpoint() {
        let dir = tempdir().unwrap();
        let (store, env_id) = store_with_env(dir.path(), "local");
        let err = config_set(
            &store,
            &OpFlags::default(),
            Some(UpdateConfigSetPayload {
                environment_id: "local".into(),
                enabled: None,
                on_notify: None,
                poll_interval_secs: None,
                plan_endpoint: None,
                push_enabled: None,
                stream_endpoint: Some("http://example.com/stream".into()),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
        assert!(store.load_update_channel(&env_id).unwrap().is_none());
    }

    #[test]
    fn config_set_rejects_blank_stream_endpoint() {
        let dir = tempdir().unwrap();
        let (store, env_id) = store_with_env(dir.path(), "local");

        let err = config_set(
            &store,
            &OpFlags::default(),
            Some(UpdateConfigSetPayload {
                environment_id: "local".into(),
                enabled: None,
                on_notify: None,
                poll_interval_secs: None,
                plan_endpoint: None,
                push_enabled: None,
                stream_endpoint: Some("   ".into()),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
        assert!(store.load_update_channel(&env_id).unwrap().is_none());

        let err2 = config_set(
            &store,
            &OpFlags::default(),
            Some(UpdateConfigSetPayload {
                environment_id: "local".into(),
                enabled: None,
                on_notify: None,
                poll_interval_secs: None,
                plan_endpoint: None,
                push_enabled: None,
                stream_endpoint: Some("".into()),
            }),
        )
        .unwrap_err();
        assert!(matches!(err2, OpError::InvalidArgument(_)), "got {err2:?}");
        assert!(store.load_update_channel(&env_id).unwrap().is_none());
    }

    // --- default plan endpoint (config-set) ---------------------------------

    #[test]
    fn config_set_enabling_without_endpoint_persists_default() {
        // An operator enables the channel but supplies no --plan-endpoint and
        // none is stored: the fleet default is persisted at write time so the
        // runtime has somewhere to poll.
        let dir = tempdir().unwrap();
        let (store, env_id) = store_with_env(dir.path(), "local");
        let out = config_set(
            &store,
            &OpFlags::default(),
            Some(UpdateConfigSetPayload {
                environment_id: "local".into(),
                enabled: Some(true),
                on_notify: None,
                poll_interval_secs: None,
                plan_endpoint: None,
                push_enabled: None,
                stream_endpoint: None,
            }),
        )
        .unwrap();
        let cfg = store.load_update_channel(&env_id).unwrap().unwrap();
        assert_eq!(
            cfg.plan_endpoint.as_deref(),
            Some(DEFAULT_PLAN_ENDPOINT),
            "enabling without an endpoint must persist the fleet default"
        );
        assert!(cfg.resolved_enabled());
        // The outcome must surface the defaulting visibly — silently pointing a
        // runtime at a Greentic-operated URL is the kind of thing that must
        // appear in the operator's output.
        assert_eq!(
            out.result["defaulted_plan_endpoint"].as_str(),
            Some(DEFAULT_PLAN_ENDPOINT),
            "outcome must carry `defaulted_plan_endpoint` so the operator sees it"
        );
        assert!(
            out.result["note"]
                .as_str()
                .unwrap_or("")
                .contains(DEFAULT_PLAN_ENDPOINT),
            "outcome note must mention the default URL"
        );
    }

    #[test]
    fn config_set_enabling_with_stored_endpoint_leaves_it_alone() {
        // An operator has already set a custom endpoint, then enables the
        // channel without re-supplying --plan-endpoint: the stored endpoint
        // must not be overwritten by the fleet default.
        let dir = tempdir().unwrap();
        let (store, _) = store_with_env(dir.path(), "local");
        let custom = "https://custom.example.com/plans/latest";
        // First: store a custom endpoint.
        config_set(
            &store,
            &OpFlags::default(),
            Some(UpdateConfigSetPayload {
                environment_id: "local".into(),
                enabled: Some(false),
                on_notify: None,
                poll_interval_secs: None,
                plan_endpoint: Some(custom.into()),
                push_enabled: None,
                stream_endpoint: None,
            }),
        )
        .unwrap();
        // Second: enable with no --plan-endpoint.
        let out = config_set(
            &store,
            &OpFlags::default(),
            Some(UpdateConfigSetPayload {
                environment_id: "local".into(),
                enabled: Some(true),
                on_notify: None,
                poll_interval_secs: None,
                plan_endpoint: None,
                push_enabled: None,
                stream_endpoint: None,
            }),
        )
        .unwrap();
        assert_eq!(
            out.result["plan_endpoint"].as_str(),
            Some(custom),
            "stored custom endpoint must not be overwritten by the default"
        );
        assert!(
            out.result.get("defaulted_plan_endpoint").is_none()
                || out.result["defaulted_plan_endpoint"].is_null(),
            "no defaulting note when the endpoint was already stored"
        );
    }

    #[test]
    fn config_set_disabling_without_endpoint_does_not_default() {
        // Disabling the channel with no endpoint must not inject the fleet
        // default — deny-by-default means a disabled channel has no source.
        let dir = tempdir().unwrap();
        let (store, env_id) = store_with_env(dir.path(), "local");
        config_set(
            &store,
            &OpFlags::default(),
            Some(UpdateConfigSetPayload {
                environment_id: "local".into(),
                enabled: Some(false),
                on_notify: None,
                poll_interval_secs: None,
                plan_endpoint: None,
                push_enabled: None,
                stream_endpoint: None,
            }),
        )
        .unwrap();
        let cfg = store.load_update_channel(&env_id).unwrap().unwrap();
        assert!(
            cfg.plan_endpoint.is_none(),
            "disabling must not inject a plan_endpoint"
        );
        assert!(!cfg.resolved_enabled());
    }

    #[test]
    fn config_set_unknown_env_is_not_found() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path()); // no env saved
        let err = config_set(
            &store,
            &OpFlags::default(),
            Some(UpdateConfigSetPayload {
                environment_id: "ghost".into(),
                enabled: Some(true),
                on_notify: None,
                poll_interval_secs: None,
                plan_endpoint: None,
                push_enabled: None,
                stream_endpoint: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::NotFound(_)), "got {err:?}");
    }

    #[test]
    fn config_schema_only_returns_schemas() {
        let flags = OpFlags {
            schema_only: true,
            ..OpFlags::default()
        };
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let s = config_set(&store, &flags, None).unwrap();
        assert_eq!(s.op, "config-set");
        assert!(s.result["properties"]["enabled"].is_object());
        let sh = config_show(&store, &flags, None).unwrap();
        assert_eq!(sh.op, "config-show");
    }

    #[test]
    fn config_set_concurrent_disjoint_updates_both_survive() {
        let dir = tempdir().unwrap();
        let (store, env_id) = store_with_env(dir.path(), "local");
        // Two operators set disjoint fields at the same time. The env flock held
        // across each read-modify-write (via `transact`) serializes them, so the
        // later writer observes the earlier writer's field and neither is lost.
        std::thread::scope(|s| {
            let a = store.clone();
            s.spawn(move || {
                config_set(
                    &a,
                    &OpFlags::default(),
                    Some(UpdateConfigSetPayload {
                        environment_id: "local".into(),
                        enabled: Some(true),
                        on_notify: None,
                        poll_interval_secs: None,
                        plan_endpoint: None,
                        push_enabled: None,
                        stream_endpoint: None,
                    }),
                )
                .unwrap();
            });
            let b = store.clone();
            s.spawn(move || {
                config_set(
                    &b,
                    &OpFlags::default(),
                    Some(UpdateConfigSetPayload {
                        environment_id: "local".into(),
                        enabled: None,
                        on_notify: Some("record-only".into()),
                        poll_interval_secs: None,
                        plan_endpoint: None,
                        push_enabled: None,
                        stream_endpoint: None,
                    }),
                )
                .unwrap();
            });
        });
        let cfg = store.load_update_channel(&env_id).unwrap().unwrap();
        assert_eq!(cfg.enabled, Some(true));
        assert_eq!(cfg.on_notify, Some(OnNotifyAction::RecordOnly));
    }

    #[test]
    fn config_set_rejects_corrupt_environment() {
        // A directory whose `environment.json` is present (so `exists` admits it)
        // but does not deserialize must be rejected fail-closed under the lock —
        // no sidecar is written for an env the store itself would reject.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env_id = EnvId::try_from("local").unwrap();
        let env_dir = dir.path().join("local");
        std::fs::create_dir_all(&env_dir).unwrap();
        std::fs::write(
            env_dir.join("environment.json"),
            b"{ not-valid environment ]",
        )
        .unwrap();
        // The shallow presence check admits the corrupt directory...
        assert!(store.exists(&env_id).unwrap());
        // ...but the validated load inside the locked transaction rejects it,
        // so the call errors and no sidecar is written.
        config_set(
            &store,
            &OpFlags::default(),
            Some(UpdateConfigSetPayload {
                environment_id: "local".into(),
                enabled: Some(true),
                on_notify: None,
                poll_interval_secs: None,
                plan_endpoint: None,
                push_enabled: None,
                stream_endpoint: None,
            }),
        )
        .unwrap_err();
        assert!(
            !env_dir.join("update-channel.json").exists(),
            "sidecar must not be written for a corrupt env"
        );
    }

    // A self-signed X.509 cert (public material only) used to exercise the
    // `status` parse path without a running CA.
    const TEST_CERT_PEM: &str = r"-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIUYapGXgtZrRNo/AWjUTX7ECfZenIwDQYJKoZIhvcNAQEL
BQAwIDEeMBwGA1UEAwwVZ3JlZW50aWMtdXBkYXRlci10ZXN0MB4XDTI2MDcwMjA4
MjkzNVoXDTM2MDYyOTA4MjkzNVowIDEeMBwGA1UEAwwVZ3JlZW50aWMtdXBkYXRl
ci10ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtIvlVwfBZr7V
GuUjcIgn4Uk+ONcdK2yraA3jhVulpYBepqhsN3bLE/XRPEOWeWdXcpfW/RQSx+sC
VFx2HWa0Ogh9pu75TnIxXlNPD/puEpWxJ9JcuLbujeAX1iGecKFUgfdKVFs3vAGG
MjN4ntvPt884TeoRlWoFdqY7xzHpWjnV4H/VLGGPo+7QaZKBLk7dCWfkGUTLFQSQ
p5utU4xLFdwB7dadhv6ZVp3aOAmfkYu3UuY7/YIYoYGZ6E2dg57UEv9sjbhdLBeO
wUpG7zisBhVcYwA9MwK65VzrCD32HCFX99XMf5Gd5VW03j2qHLyQuh4dQqKw2yCG
R2143vo4iQIDAQABo1MwUTAdBgNVHQ4EFgQUYIT+qBjsmFV4LvkTOd4NaXxNoGIw
HwYDVR0jBBgwFoAUYIT+qBjsmFV4LvkTOd4NaXxNoGIwDwYDVR0TAQH/BAUwAwEB
/zANBgkqhkiG9w0BAQsFAAOCAQEABHXHVVGIsmYL0LaQPvRafHqsjVCh8kiLh62b
qrCeqSAeXQ7YgQVmmLGV/ZzL+nbC3SoLtT0HrYcOLHsuDLbl534w6M8U7ysliZdf
tRtAPghtrI0zcQyXVaq1fPFB0zc/ALB8oq6I7oAwHBs+9n76nfcVRKifsrYqJm6E
8XeewuLxi7lCULA/FfWteIE4kbx3HqzAG98eGbVebOApyMEAnf111PwjW0VTW4QB
L/P4PeKwohc0l4sRjlkvy+o9gnnvgjsTcMPGx1UXFXM/d8AoY1WC20cofmn0RlEd
uVbcKfZbU024RZ5zYGS0n3L4l6TVqpqQzrDfXjZNzyq0r/TK8g==
-----END CERTIFICATE-----
";

    fn dev_store_env_with_tenant() -> greentic_deploy_spec::Environment {
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Secrets,
            "greentic.secrets.dev-store@1.0.0",
        ));
        env.host_config.tenant_org_id = Some("acme".to_string());
        env
    }

    // ---- materialize_bundles (pure manifest rewrite) --------------------

    #[test]
    fn materialize_uri_only_bundle_gets_local_path_and_keeps_uri() {
        // A URI-only single-revision bundle (no local path): materializing must
        // fill in `bundle_path` so apply reads local, while leaving
        // `bundle_source_uri` intact as the boot-time pull ref. This is what
        // lets a digest-matched apply run fully offline.
        let target = json!({
            "bundles": [{
                "bundle_id": "b1",
                "bundle_source_uri": "oci://registry/example:1",
                "bundle_digest": "sha256:aaa",
            }],
        });
        let mut staged = BTreeMap::new();
        staged.insert("sha256:aaa".to_string(), PathBuf::from("/staged/aaa/blob"));

        let out = materialize_bundles(&target, &staged);
        assert_eq!(out["bundles"][0]["bundle_path"], json!("/staged/aaa/blob"));
        assert_eq!(
            out["bundles"][0]["bundle_source_uri"],
            json!("oci://registry/example:1"),
            "the boot-time pull ref must survive materialization"
        );
    }

    #[test]
    fn materialize_single_revision_with_path_and_uri_overwrites_path_keeps_uri() {
        // A valid single-revision shape can carry BOTH a local `bundle_path` and
        // a `bundle_source_uri` (the boot-time pull ref). Materializing must
        // overwrite the path with the staged blob yet leave the URI intact.
        let target = json!({
            "bundles": [{
                "bundle_id": "b1",
                "bundle_path": "orig.gtbundle",
                "bundle_source_uri": "oci://registry/example:1",
                "bundle_digest": "sha256:aaa",
            }],
        });
        let mut staged = BTreeMap::new();
        staged.insert("sha256:aaa".to_string(), PathBuf::from("/staged/aaa/blob"));

        let out = materialize_bundles(&target, &staged);
        assert_eq!(out["bundles"][0]["bundle_path"], json!("/staged/aaa/blob"));
        assert_eq!(
            out["bundles"][0]["bundle_source_uri"],
            json!("oci://registry/example:1"),
            "the boot-time pull ref must survive materialization"
        );
    }

    #[test]
    fn materialize_leaves_unmatched_digest_untouched() {
        // A bundle whose digest is not in the staged set must keep its declared
        // source verbatim — apply falls back to the remote pull.
        let target = json!({
            "bundles": [{
                "bundle_id": "b1",
                "bundle_path": "orig.gtbundle",
                "bundle_digest": "sha256:zzz",
            }],
        });
        let mut staged = BTreeMap::new();
        staged.insert("sha256:aaa".to_string(), PathBuf::from("/staged/aaa/blob"));

        let out = materialize_bundles(&target, &staged);
        assert_eq!(out["bundles"][0]["bundle_path"], json!("orig.gtbundle"));
    }

    #[test]
    fn materialize_rewrites_each_revision_and_leaves_bundle_level_alone() {
        let target = json!({
            "bundles": [{
                "bundle_id": "b1",
                "revisions": [
                    { "name": "blue",  "bundle_path": "blue.gtbundle",  "bundle_digest": "sha256:aaa" },
                    { "name": "green", "bundle_path": "green.gtbundle", "bundle_digest": "sha256:bbb",
                      "bundle_source_uri": "oci://registry/green:1" },
                ],
            }],
        });
        let mut staged = BTreeMap::new();
        staged.insert("sha256:aaa".to_string(), PathBuf::from("/staged/aaa/blob"));
        staged.insert("sha256:bbb".to_string(), PathBuf::from("/staged/bbb/blob"));

        let out = materialize_bundles(&target, &staged);
        let revs = &out["bundles"][0]["revisions"];
        assert_eq!(revs[0]["bundle_path"], json!("/staged/aaa/blob"));
        assert_eq!(revs[1]["bundle_path"], json!("/staged/bbb/blob"));
        assert_eq!(
            revs[1]["bundle_source_uri"],
            json!("oci://registry/green:1")
        );
        // A multi-revision bundle carries no bundle-level path; nothing is added.
        assert!(out["bundles"][0].get("bundle_path").is_none());
    }

    #[test]
    fn materialize_target_without_bundles_is_a_noop() {
        let target = json!({ "environment": { "id": "local" } });
        let out = materialize_bundles(&target, &BTreeMap::new());
        assert_eq!(out, target);
    }

    #[test]
    fn enroll_schema_only_returns_payload_schema() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let out = enroll(
            &store,
            &OpFlags {
                schema_only: true,
                ..OpFlags::default()
            },
            None,
        )
        .unwrap();
        assert_eq!(out.op, "enroll");
        assert_eq!(out.noun, NOUN);
        assert!(out.result["properties"]["ca_url"].is_object());
    }

    #[test]
    fn status_schema_only_returns_payload_schema() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let out = status(
            &store,
            &OpFlags {
                schema_only: true,
                ..OpFlags::default()
            },
            None,
        )
        .unwrap();
        assert_eq!(out.op, "status");
        assert!(out.result["properties"]["environment_id"].is_object());
    }

    #[test]
    fn enroll_rejects_empty_ca_url_before_network() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&dev_store_env_with_tenant()).unwrap();
        let err = enroll(
            &store,
            &OpFlags::default(),
            Some(UpdatesEnrollPayload {
                environment_id: "local".into(),
                ca_url: "   ".into(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    #[test]
    fn enroll_rejects_non_http_ca_url() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&dev_store_env_with_tenant()).unwrap();
        let err = enroll(
            &store,
            &OpFlags::default(),
            Some(UpdatesEnrollPayload {
                environment_id: "local".into(),
                ca_url: "ftp://ca.example".into(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    #[test]
    fn control_url_is_acceptable_requires_https_or_loopback_http() {
        // HTTPS is always acceptable.
        assert!(control_url_is_acceptable("https://ca.example"));
        assert!(control_url_is_acceptable(
            "https://ca.example:8443/v1/enroll"
        ));
        // Plaintext HTTP only to a genuine loopback host.
        assert!(control_url_is_acceptable("http://localhost"));
        assert!(control_url_is_acceptable("http://localhost:8080/enroll"));
        assert!(control_url_is_acceptable("http://127.0.0.1:9000"));
        assert!(control_url_is_acceptable("http://127.5.5.5"));
        assert!(control_url_is_acceptable("http://[::1]:8080"));
        // Plaintext HTTP to a remote host is refused (trust-anchor MITM risk).
        assert!(!control_url_is_acceptable("http://ca.example"));
        assert!(!control_url_is_acceptable("http://ca.example:8080/enroll"));
        // A hostname that merely starts with "127." is NOT loopback.
        assert!(!control_url_is_acceptable("http://127.0.0.1.evil.com"));
        // Other schemes and empties are refused.
        assert!(!control_url_is_acceptable("ftp://ca.example"));
        assert!(!control_url_is_acceptable("ca.example"));
        assert!(!control_url_is_acceptable("https://"));
        assert!(!control_url_is_acceptable(""));
    }

    #[test]
    fn enroll_rejects_plaintext_remote_ca_url() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&dev_store_env_with_tenant()).unwrap();
        let err = enroll(
            &store,
            &OpFlags::default(),
            Some(UpdatesEnrollPayload {
                environment_id: "local".into(),
                ca_url: "http://ca.example/enroll".into(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    #[test]
    fn enroll_requires_tenant_owner() {
        // Env with a secrets pack but no tenant owner: enrollment must fail
        // closed (the cert identity is the owning tenant) before any network.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Secrets,
            "greentic.secrets.dev-store@1.0.0",
        ));
        store.save(&env).unwrap();
        let err = enroll(
            &store,
            &OpFlags::default(),
            Some(UpdatesEnrollPayload {
                environment_id: "local".into(),
                ca_url: "https://ca.example".into(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    #[test]
    fn status_reports_not_enrolled_when_no_cert_stored() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&dev_store_env_with_tenant()).unwrap();
        let out = status(
            &store,
            &OpFlags::default(),
            Some(UpdatesStatusPayload {
                environment_id: "local".into(),
            }),
        )
        .unwrap();
        assert_eq!(out.result["enrolled"], false);
    }

    #[test]
    fn status_reports_serial_and_validity_for_stored_cert() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env = dev_store_env_with_tenant();
        store.save(&env).unwrap();
        let env_id = EnvId::try_from("local").unwrap();
        // Seed the identity blob exactly where `enroll` would persist it.
        let identity = StoredIdentity {
            client_key_pem: "-----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----\n".into(),
            client_cert_pem: TEST_CERT_PEM.to_string(),
            ca_pem: "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n".into(),
            ca_url: "https://ca.example".into(),
        };
        put_env_secret(
            &store,
            &env,
            &env_id,
            DEV_STORE_KIND_PATH,
            "acme/_/tls/updater_identity",
            &serde_json::to_string(&identity).unwrap(),
        )
        .unwrap();
        let out = status(
            &store,
            &OpFlags::default(),
            Some(UpdatesStatusPayload {
                environment_id: "local".into(),
            }),
        )
        .unwrap();
        assert_eq!(out.result["enrolled"], true);
        // The reported fields come straight from parse_cert_info of the PEM.
        let info = greentic_update::tls::parse_cert_info(TEST_CERT_PEM).unwrap();
        assert_eq!(out.result["serial"].as_str().unwrap(), info.serial_hex);
        assert_eq!(
            out.result["not_after_epoch"].as_i64().unwrap(),
            info.not_after_epoch
        );
    }

    #[test]
    fn status_requires_tenant_owner() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Secrets,
            "greentic.secrets.dev-store@1.0.0",
        ));
        store.save(&env).unwrap();
        let err = status(
            &store,
            &OpFlags::default(),
            Some(UpdatesStatusPayload {
                environment_id: "local".into(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    #[test]
    fn persist_enrollment_writes_one_identity_secret_then_status_reads_it() {
        // Exercises the durable side-effect of `enroll` without a CA: build a
        // synthetic Enrollment, persist it as the single identity secret, read it
        // back through the reader's dispatch, and confirm `status` finds the cert.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env = dev_store_env_with_tenant();
        store.save(&env).unwrap();
        let env_id = EnvId::try_from("local").unwrap();

        let enrollment = greentic_update::enroll::Enrollment {
            client_key_pem: "-----BEGIN PRIVATE KEY-----\nKEYMATERIAL\n-----END PRIVATE KEY-----\n"
                .to_string(),
            client_cert_pem: TEST_CERT_PEM.to_string(),
            ca_pem: "-----BEGIN CERTIFICATE-----\nCAMATERIAL\n-----END CERTIFICATE-----\n"
                .to_string(),
            serial: "61aa465e0b59ad1368fc05a35135fb1027d97a72".to_string(),
            not_after: "2036-06-29T08:29:35Z".to_string(),
        };
        let ca_url = "https://ca.example";

        let stored = persist_enrollment(
            &store,
            &env,
            &env_id,
            DEV_STORE_KIND_PATH,
            "acme",
            ca_url,
            &enrollment,
        )
        .unwrap();

        // Exactly ONE secret is written — the whole identity as an atomic blob.
        let names: Vec<&str> = stored.iter().map(|e| e["name"].as_str().unwrap()).collect();
        assert_eq!(names, vec![IDENTITY_NAME]);
        assert_eq!(
            stored[0]["store_uri"].as_str().unwrap(),
            "secrets://local/acme/_/tls/updater_identity"
        );

        // The blob round-trips every field through the reader's dispatch.
        let identity = load_identity(&store, &env, &env_id, DEV_STORE_KIND_PATH, "acme")
            .unwrap()
            .expect("identity present after enroll");
        assert_eq!(identity.client_key_pem, enrollment.client_key_pem);
        assert_eq!(identity.client_cert_pem, TEST_CERT_PEM);
        assert_eq!(identity.ca_pem, enrollment.ca_pem);
        assert_eq!(identity.ca_url, ca_url);

        // Full producer -> consumer round-trip: `status` finds the persisted cert.
        let out = status(
            &store,
            &OpFlags::default(),
            Some(UpdatesStatusPayload {
                environment_id: "local".into(),
            }),
        )
        .unwrap();
        assert_eq!(out.result["enrolled"], true);
        let info = greentic_update::tls::parse_cert_info(TEST_CERT_PEM).unwrap();
        assert_eq!(out.result["serial"].as_str().unwrap(), info.serial_hex);
    }

    #[test]
    fn re_enrollment_rotates_the_whole_identity_atomically() {
        // Regression for the rotation-corruption hazard: a re-enrollment must
        // never leave the new private key paired with the previous certificate.
        // With the single-secret layout the stored blob is always wholly the last
        // enrollment's material — key, ca and ca_url all flip together, so there
        // is no window in which a reader sees a mismatched pair.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env = dev_store_env_with_tenant();
        store.save(&env).unwrap();
        let env_id = EnvId::try_from("local").unwrap();

        let enroll_with = |key: &str, ca: &str, ca_url: &str| {
            persist_enrollment(
                &store,
                &env,
                &env_id,
                DEV_STORE_KIND_PATH,
                "acme",
                ca_url,
                &greentic_update::enroll::Enrollment {
                    client_key_pem: key.to_string(),
                    client_cert_pem: TEST_CERT_PEM.to_string(),
                    ca_pem: ca.to_string(),
                    serial: "s".to_string(),
                    not_after: "2036-06-29T08:29:35Z".to_string(),
                },
            )
            .unwrap();
        };

        enroll_with("KEY-A", "CA-A", "https://a.example");
        enroll_with("KEY-B", "CA-B", "https://b.example");

        let identity = load_identity(&store, &env, &env_id, DEV_STORE_KIND_PATH, "acme")
            .unwrap()
            .expect("identity present after rotation");
        // Every field is the SECOND enrollment's — no field is left at "A".
        assert_eq!(identity.client_key_pem, "KEY-B");
        assert_eq!(identity.ca_pem, "CA-B");
        assert_eq!(identity.ca_url, "https://b.example");
    }

    #[test]
    fn load_identity_rejects_a_corrupt_blob() {
        // A present-but-unparseable identity is a hard error, never silently
        // downgraded to "not enrolled" (which would mask a real problem).
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env = dev_store_env_with_tenant();
        store.save(&env).unwrap();
        let env_id = EnvId::try_from("local").unwrap();

        put_env_secret(
            &store,
            &env,
            &env_id,
            DEV_STORE_KIND_PATH,
            &tls_rel_path("acme", IDENTITY_NAME),
            "not json",
        )
        .unwrap();

        let err = load_identity(&store, &env, &env_id, DEV_STORE_KIND_PATH, "acme").unwrap_err();
        assert!(matches!(err, OpError::Conflict(m) if m.contains("corrupt")));
    }

    // ---- `get` ----

    use greentic_distributor_client::signing::{TrustRoot, TrustedKey};

    /// Deterministic Ed25519 key: PKCS#8 private PEM + the matching `TrustedKey`.
    fn key_pair(seed: u8) -> (String, TrustedKey) {
        use ed25519_dalek::SigningKey;
        use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
        use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
        use greentic_distributor_client::signing::key_id_for_public_key_pem;

        let sk = SigningKey::from_bytes(&[seed; 32]);
        let priv_pem = sk.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let pub_pem = sk
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let key_id = key_id_for_public_key_pem(&pub_pem).unwrap();
        (
            priv_pem,
            TrustedKey {
                key_id,
                public_key_pem: pub_pem,
            },
        )
    }

    /// Build + sign an update plan, returning `(plan_bytes, envelope_bytes)`.
    /// `build_trust` must contain the signing key (build self-verifies).
    #[allow(clippy::too_many_arguments)]
    fn signed_plan(
        env_id: &str,
        plan_id: &str,
        sequence: u64,
        artifacts: Value,
        compat: Value,
        priv_pem: &str,
        key_id: &str,
        build_trust: &TrustRoot,
    ) -> (Vec<u8>, Vec<u8>) {
        let plan: greentic_update::plan::UpdatePlan = serde_json::from_value(json!({
            "schema": "greentic.update-plan.v1",
            "plan_id": plan_id,
            "env_id": env_id,
            "sequence": sequence,
            "created_at": "2026-07-02T00:00:00Z",
            "nonce": format!("nonce-{plan_id}"),
            "target": {"schema": "greentic.env-manifest.v1", "environment": {"id": env_id}},
            "artifacts": artifacts,
            "compat": compat,
            "rollback": {"policy": "auto", "health_timeout_s": 120, "on_fail": "restore"},
        }))
        .unwrap();
        let built =
            greentic_update::plan::build_update_plan(&plan, priv_pem, key_id, build_trust).unwrap();
        (built.plan_bytes, built.envelope_bytes)
    }

    /// Save a fresh `local` env and seed its trust root with `tk`.
    fn env_trusting(store: &LocalFsStore, tk: &TrustedKey) -> EnvId {
        env_trusting_secrets(store, tk, None)
    }

    /// Like [`env_trusting`] but optionally binds the env's `Secrets` slot to
    /// `kind` (e.g. `VAULT_SECRETS_PACK`), so the apply-time dev-store guard
    /// sees a non-dev-store backend. `None` leaves the slot unbound (custodial
    /// dev-store).
    fn env_trusting_secrets(store: &LocalFsStore, tk: &TrustedKey, kind: Option<&str>) -> EnvId {
        let mut env = make_env("local");
        if let Some(k) = kind {
            env.packs.push(make_binding(CapabilitySlot::Secrets, k));
        }
        store.save(&env).unwrap();
        let env_id = EnvId::try_from("local").unwrap();
        let env_dir = store.env_dir(&env_id).unwrap();
        store_trust_root::add_trusted_key(&env_dir, tk.clone()).unwrap();
        env_id
    }

    #[test]
    fn get_schema_only_returns_payload_schema() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let out = get(
            &store,
            &OpFlags {
                schema_only: true,
                ..OpFlags::default()
            },
            None,
        )
        .unwrap();
        assert_eq!(out.op, "get");
        assert_eq!(out.noun, NOUN);
        assert!(out.result["properties"]["plan_url"].is_object());
    }

    #[test]
    fn get_rejects_missing_plan_source() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let err = get(
            &store,
            &OpFlags::default(),
            Some(UpdatesGetPayload {
                environment_id: "local".into(),
                plan_url: None,
                plan_file: None,
                plan_sig_file: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    #[test]
    fn get_rejects_plan_signed_by_untrusted_key() {
        // Env trusts key 7; the plan is signed by key 9 (trusted only at build).
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (_priv7, tk7) = key_pair(7);
        let env_id = env_trusting(&store, &tk7);

        let (priv9, tk9) = key_pair(9);
        let build_trust = TrustRoot::new(vec![tk9.clone()]);
        let (plan_b, sig_b) = signed_plan(
            "local",
            "plan-x",
            1,
            json!([]),
            json!({}),
            &priv9,
            &tk9.key_id,
            &build_trust,
        );
        let plan_file = dir.path().join("plan.json");
        let sig_file = dir.path().join("plan.json.sig");
        std::fs::write(&plan_file, &plan_b).unwrap();
        std::fs::write(&sig_file, &sig_b).unwrap();

        let err = get(
            &store,
            &OpFlags::default(),
            Some(UpdatesGetPayload {
                environment_id: env_id.to_string(),
                plan_url: None,
                plan_file: Some(plan_file),
                plan_sig_file: Some(sig_file),
            }),
        )
        .unwrap_err();
        // Closed-by-default: the env trust root does not hold the signer.
        assert!(matches!(err, OpError::Conflict(_)));
    }

    #[test]
    fn get_rejects_plan_targeting_another_env() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (priv7, tk7) = key_pair(7);
        let env_id = env_trusting(&store, &tk7);

        let build_trust = TrustRoot::new(vec![tk7.clone()]);
        // Signed by the trusted key, but the plan targets env `other`.
        let (plan_b, sig_b) = signed_plan(
            "other",
            "plan-x",
            1,
            json!([]),
            json!({}),
            &priv7,
            &tk7.key_id,
            &build_trust,
        );
        let plan_file = dir.path().join("plan.json");
        let sig_file = dir.path().join("plan.json.sig");
        std::fs::write(&plan_file, &plan_b).unwrap();
        std::fs::write(&sig_file, &sig_b).unwrap();

        let err = get(
            &store,
            &OpFlags::default(),
            Some(UpdatesGetPayload {
                environment_id: env_id.to_string(),
                plan_url: None,
                plan_file: Some(plan_file),
                plan_sig_file: Some(sig_file),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    #[test]
    fn get_stages_zero_artifact_plan_to_staged() {
        let dir = tempdir().unwrap();
        let updates_dir = tempdir().unwrap();

        let store = LocalFsStore::new(dir.path());
        let (priv7, tk7) = key_pair(7);
        let env_id = env_trusting(&store, &tk7);

        let build_trust = TrustRoot::new(vec![tk7.clone()]);
        // No artifacts + unconstrained compat ⇒ the pipeline reaches `staged`.
        let (plan_b, sig_b) = signed_plan(
            "local",
            "plan-happy",
            1,
            json!([]),
            json!({}),
            &priv7,
            &tk7.key_id,
            &build_trust,
        );
        let plan_file = dir.path().join("plan.json");
        let sig_file = dir.path().join("plan.json.sig");
        std::fs::write(&plan_file, &plan_b).unwrap();
        std::fs::write(&sig_file, &sig_b).unwrap();

        // The test seam points the staging FSM at a tempdir (no env-var / unsafe).
        let out = get_impl(
            &store,
            &OpFlags::default(),
            Some(UpdatesGetPayload {
                environment_id: env_id.to_string(),
                plan_url: None,
                plan_file: Some(plan_file),
                plan_sig_file: Some(sig_file),
            }),
            Some(updates_dir.path()),
        )
        .unwrap();

        assert_eq!(out.op, "get");
        assert_eq!(out.result["stage"], "staged");
        assert_eq!(out.result["plan_id"], "plan-happy");
        assert_eq!(out.result["artifacts_total"], 0);
        assert_eq!(out.result["sequence"], 1);
    }

    #[test]
    fn get_rejects_target_manifest_naming_another_env() {
        // plan.env_id matches `local`, but the signed target manifest names
        // `other` — a self-inconsistent plan must be refused (fail closed).
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (priv7, tk7) = key_pair(7);
        let env_id = env_trusting(&store, &tk7);
        let build_trust = TrustRoot::new(vec![tk7.clone()]);

        let plan: greentic_update::plan::UpdatePlan = serde_json::from_value(json!({
            "schema": "greentic.update-plan.v1",
            "plan_id": "plan-mismatch",
            "env_id": "local",
            "sequence": 1,
            "created_at": "2026-07-02T00:00:00Z",
            "nonce": "n",
            "target": {"schema": "greentic.env-manifest.v1", "environment": {"id": "other"}},
            "artifacts": [],
            "compat": {},
            "rollback": {"policy": "auto", "health_timeout_s": 120, "on_fail": "restore"},
        }))
        .unwrap();
        let built =
            greentic_update::plan::build_update_plan(&plan, &priv7, &tk7.key_id, &build_trust)
                .unwrap();
        let plan_file = dir.path().join("plan.json");
        let sig_file = dir.path().join("plan.json.sig");
        std::fs::write(&plan_file, &built.plan_bytes).unwrap();
        std::fs::write(&sig_file, &built.envelope_bytes).unwrap();

        // Fails at the identity check, before the staging root is touched.
        let err = get(
            &store,
            &OpFlags::default(),
            Some(UpdatesGetPayload {
                environment_id: env_id.to_string(),
                plan_url: None,
                plan_file: Some(plan_file),
                plan_sig_file: Some(sig_file),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    #[test]
    fn get_rejects_plaintext_remote_plan_url() {
        // A remote plaintext plan_url would fetch without presenting the enrolled
        // mTLS identity — rejected before any secret read or network call.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let err = get(
            &store,
            &OpFlags::default(),
            Some(UpdatesGetPayload {
                environment_id: "local".into(),
                plan_url: Some("http://updates.example/plan".into()),
                plan_file: None,
                plan_sig_file: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    #[test]
    fn get_is_idempotent_on_reget() {
        // Re-running `get` on the same plan must resume, not error `PlanExists`.
        let dir = tempdir().unwrap();
        let updates_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (priv7, tk7) = key_pair(7);
        let env_id = env_trusting(&store, &tk7);
        let build_trust = TrustRoot::new(vec![tk7.clone()]);
        let (plan_b, sig_b) = signed_plan(
            "local",
            "plan-idem",
            1,
            json!([]),
            json!({}),
            &priv7,
            &tk7.key_id,
            &build_trust,
        );
        let plan_file = dir.path().join("plan.json");
        let sig_file = dir.path().join("plan.json.sig");
        std::fs::write(&plan_file, &plan_b).unwrap();
        std::fs::write(&sig_file, &sig_b).unwrap();

        let payload = || UpdatesGetPayload {
            environment_id: env_id.to_string(),
            plan_url: None,
            plan_file: Some(plan_file.clone()),
            plan_sig_file: Some(sig_file.clone()),
        };
        let first = get_impl(
            &store,
            &OpFlags::default(),
            Some(payload()),
            Some(updates_dir.path()),
        )
        .unwrap();
        assert_eq!(first.result["stage"], "staged");

        let second = get_impl(
            &store,
            &OpFlags::default(),
            Some(payload()),
            Some(updates_dir.path()),
        )
        .unwrap();
        assert_eq!(second.result["stage"], "staged");
        assert_eq!(second.result["plan_id"], "plan-idem");
    }

    // ---- Phase 2b: artifact download orchestration -----------------------

    /// An [`ArtifactFetcher`] stub: serves canned bytes by artifact name, can
    /// fail its first `fail_times` calls (retry testing), and counts calls.
    struct StubFetcher {
        bytes: std::collections::HashMap<String, Vec<u8>>,
        fail_times: std::cell::Cell<u32>,
        calls: std::cell::Cell<u32>,
    }

    impl StubFetcher {
        fn serving(entries: &[(&str, &[u8])]) -> Self {
            Self {
                bytes: entries
                    .iter()
                    .map(|(n, b)| (n.to_string(), b.to_vec()))
                    .collect(),
                fail_times: std::cell::Cell::new(0),
                calls: std::cell::Cell::new(0),
            }
        }
    }

    impl ArtifactFetcher for StubFetcher {
        fn fetch(
            &self,
            artifact: &greentic_update::plan::PlanArtifact,
        ) -> Result<Vec<u8>, OpError> {
            self.calls.set(self.calls.get() + 1);
            let remaining = self.fail_times.get();
            if remaining > 0 {
                self.fail_times.set(remaining - 1);
                return Err(OpError::Fetch("transient".into()));
            }
            self.bytes
                .get(&artifact.name)
                .cloned()
                .ok_or_else(|| OpError::Fetch(format!("no stub bytes for `{}`", artifact.name)))
        }
    }

    fn digest_of(bytes: &[u8]) -> String {
        format!("sha256:{}", greentic_update::plan::sha256_hex(bytes))
    }

    /// Build+sign a plan carrying `artifacts`, verify it, and admit it to a
    /// fresh staging root — returning the `Downloading` StagedPlan.
    fn downloading_plan(
        updates_dir: &std::path::Path,
        artifacts: Value,
    ) -> greentic_update::staging::StagedPlan {
        let (priv9, tk9) = key_pair(9);
        let build_trust = TrustRoot::new(vec![tk9.clone()]);
        let (plan_b, sig_b) = signed_plan(
            "local",
            "plan-dl",
            1,
            artifacts,
            json!({}),
            &priv9,
            &tk9.key_id,
            &build_trust,
        );
        let verify_trust = TrustRoot::new(vec![tk9]);
        let verified =
            greentic_update::plan::verify_update_plan(&plan_b, &sig_b, &verify_trust).unwrap();
        let root = greentic_update::staging::UpdatesRoot::open_in(updates_dir, "local").unwrap();
        root.begin(&verified, &plan_b, &sig_b).unwrap()
    }

    fn no_delay(attempts: u32) -> RetryPolicy {
        RetryPolicy {
            attempts,
            base_delay: std::time::Duration::ZERO,
        }
    }

    #[test]
    fn download_and_stage_fetches_all_and_promotes() {
        use greentic_update::staging::UpdateStage;
        let updates_dir = tempdir().unwrap();
        let (a1, a2) = (b"alpha-bytes".as_slice(), b"beta-bytes".as_slice());
        let staged = downloading_plan(
            updates_dir.path(),
            json!([
                {"name": "a1", "version": "1.0.0", "digest": digest_of(a1), "source": "file:///a1"},
                {"name": "a2", "version": "1.0.0", "digest": digest_of(a2), "source": "file:///a2"},
            ]),
        );
        let stub = StubFetcher::serving(&[("a1", a1), ("a2", a2)]);
        let arts = staged.plan().artifacts.to_vec();

        let stage = download_and_stage(&staged, &arts, &stub, no_delay(1)).unwrap();

        assert_eq!(stage, UpdateStage::Staged);
        assert_eq!(stub.calls.get(), 2, "both artifacts fetched");
        // Content-addressed blobs landed under the plan's artifacts dir.
        assert_eq!(staged.stage().unwrap(), UpdateStage::Staged);
    }

    #[test]
    fn download_and_stage_digest_mismatch_fails_closed() {
        use greentic_update::staging::UpdateStage;
        let updates_dir = tempdir().unwrap();
        // Plan declares the digest of "correct" but the fetcher returns "wrong".
        let staged = downloading_plan(
            updates_dir.path(),
            json!([
                {"name": "a1", "version": "1.0.0", "digest": digest_of(b"correct"), "source": "file:///a1"},
            ]),
        );
        let stub = StubFetcher::serving(&[("a1", b"wrong")]);
        let arts = staged.plan().artifacts.to_vec();

        let err = download_and_stage(&staged, &arts, &stub, no_delay(1)).unwrap_err();

        assert!(matches!(err, OpError::Conflict(m) if m.contains("digest mismatch")));
        // Fail-closed: the plan is NOT promoted; nothing half-staged.
        assert_eq!(staged.stage().unwrap(), UpdateStage::Downloading);
    }

    #[test]
    fn download_and_stage_resumes_without_refetching() {
        use greentic_update::staging::UpdateStage;
        let updates_dir = tempdir().unwrap();
        let staged = downloading_plan(
            updates_dir.path(),
            json!([{"name": "a1", "version": "1.0.0", "digest": digest_of(b"x"), "source": "file:///a1"}]),
        );
        // Simulate a completed prior run: already promoted to `staged`.
        staged.transition(UpdateStage::Inbox).unwrap();
        staged.transition(UpdateStage::Staged).unwrap();

        let stub = StubFetcher::serving(&[("a1", b"x")]);
        let arts = staged.plan().artifacts.to_vec();
        let stage = download_and_stage(&staged, &arts, &stub, no_delay(1)).unwrap();

        assert_eq!(stage, UpdateStage::Staged);
        assert_eq!(stub.calls.get(), 0, "already-staged plan must not re-fetch");
    }

    #[test]
    fn fetch_with_retry_retries_transient_then_succeeds() {
        let stub = StubFetcher::serving(&[("a1", b"ok")]);
        stub.fail_times.set(2); // fail twice, then succeed on the 3rd try
        let artifact: greentic_update::plan::PlanArtifact = serde_json::from_value(
            json!({"name": "a1", "version": "1.0.0", "digest": digest_of(b"ok"), "source": "file:///a1"}),
        )
        .unwrap();

        let bytes = fetch_with_retry(&stub, &artifact, no_delay(3)).unwrap();

        assert_eq!(bytes, b"ok");
        assert_eq!(stub.calls.get(), 3);
    }

    #[test]
    fn fetch_with_retry_exhausts_attempts_and_returns_last_error() {
        let stub = StubFetcher::serving(&[("a1", b"ok")]);
        stub.fail_times.set(99); // never succeeds within the budget
        let artifact: greentic_update::plan::PlanArtifact = serde_json::from_value(
            json!({"name": "a1", "version": "1.0.0", "digest": digest_of(b"ok"), "source": "file:///a1"}),
        )
        .unwrap();

        let err = fetch_with_retry(&stub, &artifact, no_delay(2)).unwrap_err();

        assert!(matches!(err, OpError::Fetch(_)));
        assert_eq!(stub.calls.get(), 2, "exactly `attempts` tries");
    }

    #[test]
    fn dist_fetcher_rejects_artifact_without_source() {
        // The real fetcher fails closed (before any network) on an artifact that
        // declares no `source` — online `get` cannot materialize it.
        let artifact: greentic_update::plan::PlanArtifact = serde_json::from_value(
            json!({"name": "a1", "version": "1.0.0", "digest": digest_of(b"x")}),
        )
        .unwrap();
        let err = DistArtifactFetcher::new().fetch(&artifact).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(m) if m.contains("no source")));
    }

    #[test]
    fn dist_fetcher_rejects_disallowed_scheme() {
        // A signed plan must not make the operator read local files: file:// and
        // bare paths are refused before any resolve/fetch (no network).
        for src in ["file:///etc/passwd", "/etc/passwd", "repo://x", "store://y"] {
            let artifact: greentic_update::plan::PlanArtifact = serde_json::from_value(
                json!({"name": "a1", "version": "1.0.0", "digest": digest_of(b"x"), "source": src}),
            )
            .unwrap();
            let err = DistArtifactFetcher::new().fetch(&artifact).unwrap_err();
            assert!(
                matches!(err, OpError::InvalidArgument(m) if m.contains("allowed remote scheme")),
                "source `{src}` should be rejected by scheme"
            );
        }
    }

    #[test]
    fn reject_oversize_caps_large_artifacts() {
        let artifact: greentic_update::plan::PlanArtifact = serde_json::from_value(
            json!({"name": "big", "version": "1.0.0", "digest": digest_of(b"x")}),
        )
        .unwrap();
        assert!(reject_oversize(&artifact, MAX_ARTIFACT_BYTES).is_ok());
        assert!(matches!(
            reject_oversize(&artifact, MAX_ARTIFACT_BYTES + 1),
            Err(OpError::Fetch(_))
        ));
    }

    #[test]
    fn reject_unsized_or_oversize_requires_a_known_size() {
        let artifact: greentic_update::plan::PlanArtifact = serde_json::from_value(
            json!({"name": "a", "version": "1.0.0", "digest": digest_of(b"x")}),
        )
        .unwrap();
        // A known, in-bounds size passes the pre-fetch gate.
        assert!(reject_unsized_or_oversize(&artifact, 1).is_ok());
        assert!(reject_unsized_or_oversize(&artifact, MAX_ARTIFACT_BYTES).is_ok());
        // Unknown size (0) is refused *before* any fetch — the body cannot be
        // bounded up front, so we never stream it to disk.
        assert!(matches!(
            reject_unsized_or_oversize(&artifact, 0),
            Err(OpError::Fetch(m)) if m.contains("no declared size")
        ));
        // Over the cap is still refused.
        assert!(matches!(
            reject_unsized_or_oversize(&artifact, MAX_ARTIFACT_BYTES + 1),
            Err(OpError::Fetch(_))
        ));
    }

    // ---- Phase 2b: admit_or_resume re-gating (Codex #418) -----------------

    fn verify_with(
        plan_b: &[u8],
        sig_b: &[u8],
        tk: &TrustedKey,
    ) -> greentic_update::plan::VerifiedUpdatePlan {
        greentic_update::plan::verify_update_plan(plan_b, sig_b, &TrustRoot::new(vec![tk.clone()]))
            .unwrap()
    }

    /// Sign + verify a zero-artifact plan for env `local` under key `tk`.
    fn signed_local(
        plan_id: &str,
        sequence: u64,
        priv_pem: &str,
        tk: &TrustedKey,
    ) -> (Vec<u8>, Vec<u8>, greentic_update::plan::VerifiedUpdatePlan) {
        let build_trust = TrustRoot::new(vec![tk.clone()]);
        let (p, s) = signed_plan(
            "local",
            plan_id,
            sequence,
            json!([]),
            json!({}),
            priv_pem,
            &tk.key_id,
            &build_trust,
        );
        let v = verify_with(&p, &s, tk);
        (p, s, v)
    }

    #[test]
    fn admit_or_resume_regates_stranded_downgrade() {
        use greentic_update::staging::UpdateStage;
        let updates_dir = tempdir().unwrap();
        let (priv9, tk9) = key_pair(9);
        let root =
            greentic_update::staging::UpdatesRoot::open_in(updates_dir.path(), "local").unwrap();

        // A newer plan (seq 6) is already Applied.
        let (pa, sa, va) = signed_local("applied", 6, &priv9, &tk9);
        let applied = root.begin(&va, &pa, &sa).unwrap();
        applied.transition(UpdateStage::Inbox).unwrap();
        applied.transition(UpdateStage::Staged).unwrap();
        applied.transition(UpdateStage::Applying).unwrap();
        applied.transition(UpdateStage::Applied).unwrap();

        // An older plan (seq 5) got stranded at `downloading` before that apply.
        let (ps, ss, vs) = signed_local("stale", 5, &priv9, &tk9);
        root.begin(&vs, &ps, &ss).unwrap();
        assert_eq!(
            root.load("stale").unwrap().unwrap().stage().unwrap(),
            UpdateStage::Downloading
        );

        // Resuming it must RE-GATE and reject the now-downgrade — not promote it.
        let err = admit_or_resume(&root, &vs, &ps, &ss).unwrap_err();
        assert!(matches!(err, OpError::Conflict(m) if m.contains("rejected")));
    }

    #[test]
    fn admit_or_resume_refuses_terminal_plan() {
        use greentic_update::staging::UpdateStage;
        let updates_dir = tempdir().unwrap();
        let (priv9, tk9) = key_pair(9);
        let root =
            greentic_update::staging::UpdatesRoot::open_in(updates_dir.path(), "local").unwrap();

        let (p, s, v) = signed_local("term", 1, &priv9, &tk9);
        let staged = root.begin(&v, &p, &s).unwrap();
        staged.transition(UpdateStage::Rejected).unwrap();

        let err = admit_or_resume(&root, &v, &p, &s).unwrap_err();
        assert!(matches!(err, OpError::Conflict(m) if m.contains("not resuming")));
    }

    #[test]
    fn admit_or_resume_returns_promoted_plan_as_is() {
        use greentic_update::staging::UpdateStage;
        let updates_dir = tempdir().unwrap();
        let (priv9, tk9) = key_pair(9);
        let root =
            greentic_update::staging::UpdatesRoot::open_in(updates_dir.path(), "local").unwrap();

        // A fully-staged plan (admission already ran at begin) is idempotently
        // returned as-is — NOT re-gated (which could wrongly reject it later).
        let (p, s, v) = signed_local("done", 1, &priv9, &tk9);
        let staged = root.begin(&v, &p, &s).unwrap();
        staged.transition(UpdateStage::Inbox).unwrap();
        staged.transition(UpdateStage::Staged).unwrap();

        let resumed = admit_or_resume(&root, &v, &p, &s).unwrap();
        assert_eq!(resumed.stage().unwrap(), UpdateStage::Staged);
    }

    // ---- Phase 3: op updates apply ----------------------------------------

    /// Build + sign a plan with a custom target manifest (for apply tests that
    /// need a non-minimal manifest — e.g. a bundle that fails to resolve).
    #[allow(clippy::too_many_arguments)]
    fn signed_plan_target(
        env_id: &str,
        plan_id: &str,
        sequence: u64,
        target: Value,
        priv_pem: &str,
        key_id: &str,
        build_trust: &TrustRoot,
    ) -> (Vec<u8>, Vec<u8>) {
        let plan: greentic_update::plan::UpdatePlan = serde_json::from_value(json!({
            "schema": "greentic.update-plan.v1",
            "plan_id": plan_id,
            "env_id": env_id,
            "sequence": sequence,
            "created_at": "2026-07-02T00:00:00Z",
            "nonce": format!("nonce-{plan_id}"),
            "target": target,
            "artifacts": [],
            "compat": {},
            "rollback": {"policy": "auto", "health_timeout_s": 120, "on_fail": "restore"},
        }))
        .unwrap();
        let built =
            greentic_update::plan::build_update_plan(&plan, priv_pem, key_id, build_trust).unwrap();
        (built.plan_bytes, built.envelope_bytes)
    }

    /// Stage a signed zero-artifact plan for `local` directly to `Staged`
    /// (bypasses the network path of `get`, same on-disk result). The env must
    /// already trust `tk`.
    fn stage_local(
        updates_root: &std::path::Path,
        plan_id: &str,
        sequence: u64,
        priv_pem: &str,
        tk: &TrustedKey,
    ) {
        let (p, s, v) = signed_local(plan_id, sequence, priv_pem, tk);
        let root = greentic_update::staging::UpdatesRoot::open_in(updates_root, "local").unwrap();
        let staged = root.begin(&v, &p, &s).unwrap();
        advance_to_staged(&staged).unwrap();
    }

    /// Load a staged plan's on-disk stage.
    fn on_disk_stage(
        updates_root: &std::path::Path,
        plan_id: &str,
    ) -> greentic_update::staging::UpdateStage {
        greentic_update::staging::UpdatesRoot::open_in(updates_root, "local")
            .unwrap()
            .load(plan_id)
            .unwrap()
            .unwrap()
            .stage()
            .unwrap()
    }

    #[test]
    fn apply_schema_only_returns_payload_schema() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let out = apply_updates(
            &store,
            &OpFlags {
                schema_only: true,
                ..OpFlags::default()
            },
            None,
        )
        .unwrap();
        assert_eq!(out.op, "apply");
        assert_eq!(out.noun, NOUN);
        assert!(out.result["properties"]["plan_id"].is_object());
    }

    #[test]
    fn apply_plan_not_found_is_not_found() {
        let dir = tempdir().unwrap();
        let updates_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (_priv7, tk7) = key_pair(7);
        env_trusting(&store, &tk7);
        let err = apply_updates_impl(
            &store,
            &OpFlags::default(),
            Some(ApplyUpdatesPayload {
                environment_id: "local".into(),
                plan_id: "ghost".into(),
            }),
            Some(updates_dir.path()),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::NotFound(_)));
    }

    #[test]
    fn apply_happy_path_zero_artifact_converges_and_marks_applied() {
        use greentic_update::staging::UpdateStage;
        let dir = tempdir().unwrap();
        let updates_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (priv7, tk7) = key_pair(7);
        let env_id = env_trusting(&store, &tk7);
        stage_local(updates_dir.path(), "plan-1", 1, &priv7, &tk7);

        let out = apply_updates_impl(
            &store,
            &OpFlags::default(),
            Some(ApplyUpdatesPayload {
                environment_id: "local".into(),
                plan_id: "plan-1".into(),
            }),
            Some(updates_dir.path()),
        )
        .unwrap();

        assert_eq!(out.op, "apply");
        assert_eq!(out.result["stage"], "applied");
        assert_eq!(out.result["plan_id"], "plan-1");
        assert!(out.result["snapshot_id"].as_str().is_some());

        // On-disk FSM marker advanced to Applied.
        assert_eq!(
            on_disk_stage(updates_dir.path(), "plan-1"),
            UpdateStage::Applied
        );
        // A pre-apply snapshot was captured, and a deployer-layer audit event
        // was written for the mutation.
        let env_dir = store.env_dir(&env_id).unwrap();
        assert!(env_dir.join("snapshots").is_dir(), "snapshot must exist");
        let audit = std::fs::read_to_string(env_dir.join("audit").join("events.jsonl")).unwrap();
        assert!(
            audit.contains("plan-1"),
            "audit must record the apply: {audit}"
        );
    }

    #[test]
    fn apply_annotates_binaries_it_does_not_install() {
        use greentic_update::staging::{UpdateStage, UpdatesRoot};
        let dir = tempdir().unwrap();
        let updates_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (priv7, tk7) = key_pair(7);
        env_trusting(&store, &tk7);

        // A binary-carrying `plan-build`-style output: no content artifacts, a
        // valid minimal target, one binary. `op updates apply` converges the
        // (empty) content but MUST surface that it did not install the binary,
        // so the "applied" result is never misread as a completed self-update.
        let build_trust = TrustRoot::new(vec![tk7.clone()]);
        let plan: greentic_update::plan::UpdatePlan = serde_json::from_value(json!({
            "schema": "greentic.update-plan.v1",
            "plan_id": "plan-bin",
            "env_id": "local",
            "sequence": 1,
            "created_at": "2026-07-02T00:00:00Z",
            "nonce": "nonce-plan-bin",
            "target": {"schema": "greentic.env-manifest.v1", "environment": {"id": "local"}},
            "artifacts": [],
            "binaries": [{
                "name": "greentic-start",
                "version": "1.1.9",
                "target": "x86_64-unknown-linux-gnu",
                "digest": "sha256:abc123",
                "source": "https://example.test/greentic-start.tgz"
            }],
            "compat": {},
            "rollback": {"policy": "auto", "health_timeout_s": 120, "on_fail": "restore"},
        }))
        .unwrap();
        let built =
            greentic_update::plan::build_update_plan(&plan, &priv7, &tk7.key_id, &build_trust)
                .unwrap();
        let verified = verify_with(&built.plan_bytes, &built.envelope_bytes, &tk7);
        let root = UpdatesRoot::open_in(updates_dir.path(), "local").unwrap();
        let staged = root
            .begin(&verified, &built.plan_bytes, &built.envelope_bytes)
            .unwrap();
        advance_to_staged(&staged).unwrap();

        let out = apply_updates_impl(
            &store,
            &OpFlags::default(),
            Some(ApplyUpdatesPayload {
                environment_id: "local".into(),
                plan_id: "plan-bin".into(),
            }),
            Some(updates_dir.path()),
        )
        .unwrap();

        // Content still converges + marks applied ...
        assert_eq!(out.result["stage"], "applied");
        assert_eq!(
            on_disk_stage(updates_dir.path(), "plan-bin"),
            UpdateStage::Applied
        );
        // ... but the uninstalled binary is surfaced.
        let bins = out.result["binaries_not_applied"]
            .as_array()
            .expect("binaries_not_applied must be present when the plan carries binaries");
        assert_eq!(bins.len(), 1);
        assert_eq!(bins[0]["name"], "greentic-start");
        assert_eq!(bins[0]["version"], "1.1.9");
        assert_eq!(bins[0]["target"], "x86_64-unknown-linux-gnu");
    }

    #[test]
    fn apply_transition_failure_returns_honest_recover_error() {
        // Exercise Case B: run_manifest_apply succeeds (env content IS mutated),
        // but the applying -> applied transition persistently fails. The error
        // must contain "recover" and NOT claim the apply itself failed.
        use greentic_update::staging::UpdateStage;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let updates_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (priv7, tk7) = key_pair(7);
        let env_id = env_trusting(&store, &tk7);
        stage_local(updates_dir.path(), "plan-stuck", 1, &priv7, &tk7);

        // Resolve the on-disk plan directory so we can chmod it read-only from
        // inside the fault hook, preventing `state.json` writes.
        let plan_dir = greentic_update::staging::UpdatesRoot::open_in(updates_dir.path(), "local")
            .unwrap()
            .load("plan-stuck")
            .unwrap()
            .unwrap()
            .dir()
            .to_path_buf();

        // Install a fault hook that fires AFTER run_manifest_apply succeeds but
        // BEFORE the transition retry loop. Making the plan dir read-only
        // prevents `state.json` from being rewritten, so the transition fails
        // with an I/O error.
        let hook_dir = plan_dir.clone();
        PRE_APPLIED_TRANSITION_HOOK.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                std::fs::set_permissions(&hook_dir, std::fs::Permissions::from_mode(0o500))
                    .expect("chmod plan dir read-only");
            }));
        });

        let err = apply_updates_impl(
            &store,
            &OpFlags::default(),
            Some(ApplyUpdatesPayload {
                environment_id: "local".into(),
                plan_id: "plan-stuck".into(),
            }),
            Some(updates_dir.path()),
        )
        .unwrap_err();

        // Clean up the hook so it does not interfere with other tests.
        PRE_APPLIED_TRANSITION_HOOK.with(|h| {
            *h.borrow_mut() = None;
        });
        // Restore write permission so tempdir cleanup succeeds.
        std::fs::set_permissions(&plan_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        // The error must mention `recover` and must NOT claim the apply failed.
        let msg = format!("{err}");
        assert!(
            msg.contains("recover"),
            "error must point at `op updates recover`: {msg}"
        );
        assert!(
            msg.contains("applied successfully"),
            "error must state content was applied: {msg}"
        );

        // The on-disk stage is stuck at Applying (Case B), NOT Applied.
        assert_eq!(
            on_disk_stage(updates_dir.path(), "plan-stuck"),
            UpdateStage::Applying
        );

        // The env content WAS applied — a snapshot was captured pre-mutation.
        let env_dir = store.env_dir(&env_id).unwrap();
        assert!(
            env_dir.join("snapshots").is_dir(),
            "snapshot must exist (env was mutated)"
        );
    }

    #[test]
    fn apply_rejects_already_applied_plan() {
        let dir = tempdir().unwrap();
        let updates_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (priv7, tk7) = key_pair(7);
        env_trusting(&store, &tk7);
        stage_local(updates_dir.path(), "plan-1", 1, &priv7, &tk7);

        let payload = ApplyUpdatesPayload {
            environment_id: "local".into(),
            plan_id: "plan-1".into(),
        };
        apply_updates_impl(
            &store,
            &OpFlags::default(),
            Some(payload.clone()),
            Some(updates_dir.path()),
        )
        .unwrap();
        // Re-applying a terminal (Applied) plan is refused by the stage gate.
        let err = apply_updates_impl(
            &store,
            &OpFlags::default(),
            Some(payload),
            Some(updates_dir.path()),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(m) if m.contains("not `staged`")));
    }

    #[test]
    fn apply_rejects_retryably_when_plan_already_applying() {
        use greentic_update::staging::UpdateStage;
        let dir = tempdir().unwrap();
        let updates_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (priv7, tk7) = key_pair(7);
        env_trusting(&store, &tk7);
        stage_local(updates_dir.path(), "plan-1", 1, &priv7, &tk7);
        // A same-plan apply is already in flight (or a prior one did not finish):
        // the plan sits in Applying.
        greentic_update::staging::UpdatesRoot::open_in(updates_dir.path(), "local")
            .unwrap()
            .load("plan-1")
            .unwrap()
            .unwrap()
            .transition(UpdateStage::Applying)
            .unwrap();

        let err = apply_updates_impl(
            &store,
            &OpFlags::default(),
            Some(ApplyUpdatesPayload {
                environment_id: "local".into(),
                plan_id: "plan-1".into(),
            }),
            Some(updates_dir.path()),
        )
        .unwrap_err();
        // Retryable conflict — NOT a destructive self-heal. Auto-failing the
        // marker here could strand a live concurrent apply (env mutated, marker
        // Failed, sequence never advanced).
        assert!(matches!(err, OpError::Conflict(m) if m.contains("already `applying`")));
        // The plan is left untouched — still Applying.
        assert_eq!(
            on_disk_stage(updates_dir.path(), "plan-1"),
            UpdateStage::Applying
        );
    }

    #[test]
    fn apply_rejects_swapped_plan_via_hash_cross_check() {
        use greentic_update::staging::UpdateStage;
        let dir = tempdir().unwrap();
        let updates_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (priv7, tk7) = key_pair(7);
        env_trusting(&store, &tk7);
        stage_local(updates_dir.path(), "plan-1", 1, &priv7, &tk7);

        // Swap BOTH plan.json and its sidecar for a DIFFERENT, validly-signed
        // plan (same id, different sequence ⇒ different bytes). `verify_update_plan`
        // accepts it, but its hash differs from the digest recorded at staging.
        let build_trust = TrustRoot::new(vec![tk7.clone()]);
        let (p2, s2) = signed_plan(
            "local",
            "plan-1",
            2,
            json!([]),
            json!({}),
            &priv7,
            &tk7.key_id,
            &build_trust,
        );
        let plan_dir = greentic_update::staging::UpdatesRoot::open_in(updates_dir.path(), "local")
            .unwrap()
            .load("plan-1")
            .unwrap()
            .unwrap()
            .dir()
            .to_path_buf();
        std::fs::write(plan_dir.join("plan.json"), &p2).unwrap();
        std::fs::write(plan_dir.join("plan.json.sig"), &s2).unwrap();

        let err = apply_updates_impl(
            &store,
            &OpFlags::default(),
            Some(ApplyUpdatesPayload {
                environment_id: "local".into(),
                plan_id: "plan-1".into(),
            }),
            Some(updates_dir.path()),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(m) if m.contains("hash changed")));
        assert_eq!(
            on_disk_stage(updates_dir.path(), "plan-1"),
            UpdateStage::Rejected
        );
    }

    #[test]
    fn apply_rejects_tampered_artifact_blob() {
        use greentic_update::staging::{UpdateStage, UpdatesRoot};
        let dir = tempdir().unwrap();
        let updates_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (priv7, tk7) = key_pair(7);
        env_trusting(&store, &tk7);

        let payload = b"the-artifact-bytes";
        let art_digest = format!("sha256:{}", greentic_update::plan::sha256_hex(payload));
        let build_trust = TrustRoot::new(vec![tk7.clone()]);
        let (p, s) = signed_plan(
            "local",
            "plan-art",
            1,
            json!([{"name": "pack-a", "version": "1.0.0", "digest": art_digest, "source": "oci://x/y:1"}]),
            json!({}),
            &priv7,
            &tk7.key_id,
            &build_trust,
        );
        let v = verify_with(&p, &s, &tk7);
        let root = UpdatesRoot::open_in(updates_dir.path(), "local").unwrap();
        let staged = root.begin(&v, &p, &s).unwrap();
        staged.put_artifact(&v.plan.artifacts[0], payload).unwrap();
        advance_to_staged(&staged).unwrap();
        // Corrupt the staged blob after it passed the ingest hash check.
        let blob = staged.artifact_blob_path(&v.plan.artifacts[0]).unwrap();
        std::fs::write(&blob, b"corrupted").unwrap();

        let err = apply_updates_impl(
            &store,
            &OpFlags::default(),
            Some(ApplyUpdatesPayload {
                environment_id: "local".into(),
                plan_id: "plan-art".into(),
            }),
            Some(updates_dir.path()),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(m) if m.contains("integrity")));
        assert_eq!(
            on_disk_stage(updates_dir.path(), "plan-art"),
            UpdateStage::Rejected
        );
    }

    #[test]
    fn apply_regates_downgrade_against_applied_set() {
        use greentic_update::staging::UpdateStage;
        let dir = tempdir().unwrap();
        let updates_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (priv7, tk7) = key_pair(7);
        env_trusting(&store, &tk7);

        // Both staged BEFORE either applies (so neither is rejected at stage).
        stage_local(updates_dir.path(), "plan-a", 2, &priv7, &tk7);
        stage_local(updates_dir.path(), "plan-b", 1, &priv7, &tk7);

        // Apply the newer plan first ⇒ latest_applied_sequence = 2.
        apply_updates_impl(
            &store,
            &OpFlags::default(),
            Some(ApplyUpdatesPayload {
                environment_id: "local".into(),
                plan_id: "plan-a".into(),
            }),
            Some(updates_dir.path()),
        )
        .unwrap();

        // Applying the older plan is now a downgrade ⇒ rejected at apply time.
        let err = apply_updates_impl(
            &store,
            &OpFlags::default(),
            Some(ApplyUpdatesPayload {
                environment_id: "local".into(),
                plan_id: "plan-b".into(),
            }),
            Some(updates_dir.path()),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)));
        assert_eq!(
            on_disk_stage(updates_dir.path(), "plan-b"),
            UpdateStage::Rejected
        );
    }

    #[test]
    fn apply_rejects_concurrent_applying_plan() {
        use greentic_update::staging::{UpdateStage, UpdatesRoot};
        let dir = tempdir().unwrap();
        let updates_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (priv7, tk7) = key_pair(7);
        env_trusting(&store, &tk7);

        // Two staged plans; park one at `applying` (an in-flight apply on this
        // env). begin_apply_checked's single-flight gate must then refuse the
        // other — atomically, under the staging lock.
        stage_local(updates_dir.path(), "plan-a", 1, &priv7, &tk7);
        stage_local(updates_dir.path(), "plan-b", 2, &priv7, &tk7);
        let root = UpdatesRoot::open_in(updates_dir.path(), "local").unwrap();
        root.load("plan-a")
            .unwrap()
            .unwrap()
            .transition(UpdateStage::Applying)
            .unwrap();

        let err = apply_updates_impl(
            &store,
            &OpFlags::default(),
            Some(ApplyUpdatesPayload {
                environment_id: "local".into(),
                plan_id: "plan-b".into(),
            }),
            Some(updates_dir.path()),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(m) if m.contains("single-flight")));
        // plan-b stays Staged (single-flight is retryable, not fatal); plan-a is
        // untouched — neither the env nor the losing plan was mutated.
        assert_eq!(
            on_disk_stage(updates_dir.path(), "plan-b"),
            UpdateStage::Staged
        );
        assert_eq!(
            on_disk_stage(updates_dir.path(), "plan-a"),
            UpdateStage::Applying
        );
    }

    #[test]
    fn apply_rolls_back_and_fails_plan_on_apply_error() {
        use greentic_update::staging::{UpdateStage, UpdatesRoot};
        let dir = tempdir().unwrap();
        let updates_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (priv7, tk7) = key_pair(7);
        let env_id = env_trusting(&store, &tk7);

        // A valid, digest-pinned manifest whose bundle artifact does not exist
        // ⇒ env_apply errors at resolve time (after the snapshot is taken).
        let bad_target = json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": "local"},
            "bundles": [{
                "bundle_id": "b1",
                "bundle_path": "/nonexistent/missing.gtbundle",
                "bundle_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            }]
        });
        let build_trust = TrustRoot::new(vec![tk7.clone()]);
        let (p, s) = signed_plan_target(
            "local",
            "plan-bad",
            1,
            bad_target,
            &priv7,
            &tk7.key_id,
            &build_trust,
        );
        let v = verify_with(&p, &s, &tk7);
        let root = UpdatesRoot::open_in(updates_dir.path(), "local").unwrap();
        let staged = root.begin(&v, &p, &s).unwrap();
        advance_to_staged(&staged).unwrap();

        let err = apply_updates_impl(
            &store,
            &OpFlags::default(),
            Some(ApplyUpdatesPayload {
                environment_id: "local".into(),
                plan_id: "plan-bad".into(),
            }),
            Some(updates_dir.path()),
        )
        .unwrap_err();
        // The env was rolled back and the plan failed.
        assert!(matches!(err, OpError::Conflict(m) if m.contains("rolled back")));
        assert_eq!(
            on_disk_stage(updates_dir.path(), "plan-bad"),
            UpdateStage::Failed
        );
        assert!(store.env_dir(&env_id).unwrap().join("snapshots").is_dir());
    }

    #[test]
    fn apply_rejects_secrets_when_backend_not_dev_store() {
        use greentic_update::staging::{UpdateStage, UpdatesRoot};
        let dir = tempdir().unwrap();
        let updates_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (priv7, tk7) = key_pair(7);
        // Env's Secrets slot is bound to Vault, so secret writes land outside the
        // P0b snapshot ⇒ secrets[] is refused fail-closed, and the plan is left
        // Rejected pre-mutation.
        env_trusting_secrets(&store, &tk7, Some(crate::defaults::VAULT_SECRETS_PACK));

        let target = json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": "local"},
            "secrets": [{"path": "acme/_/tls/foo", "from_env": "FOO"}]
        });
        let build_trust = TrustRoot::new(vec![tk7.clone()]);
        let (p, s) = signed_plan_target(
            "local",
            "plan-sec",
            1,
            target,
            &priv7,
            &tk7.key_id,
            &build_trust,
        );
        let v = verify_with(&p, &s, &tk7);
        let root = UpdatesRoot::open_in(updates_dir.path(), "local").unwrap();
        let staged = root.begin(&v, &p, &s).unwrap();
        advance_to_staged(&staged).unwrap();

        let err = apply_updates_impl(
            &store,
            &OpFlags::default(),
            Some(ApplyUpdatesPayload {
                environment_id: "local".into(),
                plan_id: "plan-sec".into(),
            }),
            Some(updates_dir.path()),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(m) if m.contains("non-dev-store backend")));
        // Refused pre-mutation ⇒ marked Rejected, env untouched.
        assert_eq!(
            on_disk_stage(updates_dir.path(), "plan-sec"),
            UpdateStage::Rejected
        );
    }

    #[test]
    fn apply_rejects_endpoints_when_backend_not_dev_store() {
        use greentic_update::staging::{UpdateStage, UpdatesRoot};
        let dir = tempdir().unwrap();
        let updates_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (priv7, tk7) = key_pair(7);
        // Telegram-class endpoints auto-provision a webhook secret; under a Vault
        // Secrets binding that write escapes the snapshot ⇒ refused fail-closed.
        env_trusting_secrets(&store, &tk7, Some(crate::defaults::VAULT_SECRETS_PACK));

        let target = json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": "local"},
            "messaging_endpoints": [{"name": "tg", "provider_type": "messaging.telegram.bot"}]
        });
        let build_trust = TrustRoot::new(vec![tk7.clone()]);
        let (p, s) = signed_plan_target(
            "local",
            "plan-ep",
            1,
            target,
            &priv7,
            &tk7.key_id,
            &build_trust,
        );
        let v = verify_with(&p, &s, &tk7);
        let root = UpdatesRoot::open_in(updates_dir.path(), "local").unwrap();
        let staged = root.begin(&v, &p, &s).unwrap();
        advance_to_staged(&staged).unwrap();

        let err = apply_updates_impl(
            &store,
            &OpFlags::default(),
            Some(ApplyUpdatesPayload {
                environment_id: "local".into(),
                plan_id: "plan-ep".into(),
            }),
            Some(updates_dir.path()),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(m) if m.contains("non-dev-store backend")));
        assert_eq!(
            on_disk_stage(updates_dir.path(), "plan-ep"),
            UpdateStage::Rejected
        );
    }

    #[test]
    fn apply_rejects_unpinned_bundle() {
        use greentic_update::staging::{UpdateStage, UpdatesRoot};
        let dir = tempdir().unwrap();
        let updates_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (priv7, tk7) = key_pair(7);
        env_trusting(&store, &tk7);

        // A bundle with no bundle_digest is refused: apply-updates requires
        // update-plan bundles to be digest-pinned.
        let target = json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": "local"},
            "bundles": [{"bundle_id": "b1", "bundle_path": "/some/local.gtbundle"}]
        });
        let build_trust = TrustRoot::new(vec![tk7.clone()]);
        let (p, s) = signed_plan_target(
            "local",
            "plan-unpinned",
            1,
            target,
            &priv7,
            &tk7.key_id,
            &build_trust,
        );
        let v = verify_with(&p, &s, &tk7);
        let root = UpdatesRoot::open_in(updates_dir.path(), "local").unwrap();
        let staged = root.begin(&v, &p, &s).unwrap();
        advance_to_staged(&staged).unwrap();

        let err = apply_updates_impl(
            &store,
            &OpFlags::default(),
            Some(ApplyUpdatesPayload {
                environment_id: "local".into(),
                plan_id: "plan-unpinned".into(),
            }),
            Some(updates_dir.path()),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(m) if m.contains("bundle_digest")));
        assert_eq!(
            on_disk_stage(updates_dir.path(), "plan-unpinned"),
            UpdateStage::Rejected
        );
    }

    // ---- precise dev-store-secret guard (check_applyable_manifest) ----

    fn parse_manifest(v: Value) -> EnvManifest {
        serde_json::from_value(v).expect("valid env-manifest")
    }

    fn secrets_manifest() -> EnvManifest {
        parse_manifest(json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": "local"},
            "secrets": [{"path": "acme/_/tls/foo", "from_env": "FOO"}]
        }))
    }

    #[test]
    fn guard_accepts_secret_writes_on_dev_store_env() {
        // No Secrets binding ⇒ custodial dev-store; no manifest rebind; no
        // override; no symlinked candidate ⇒ the writes land in the snapshotted
        // dev-store, so both secrets[] and messaging_endpoints[] are applyable.
        let env = make_env("local");
        let td = tempdir().unwrap();
        check_applyable_manifest(&env, td.path(), &secrets_manifest(), false).unwrap();

        let endpoints = parse_manifest(json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": "local"},
            "messaging_endpoints": [{"name": "tg", "provider_type": "messaging.telegram.bot"}]
        }));
        check_applyable_manifest(&env, td.path(), &endpoints, false).unwrap();
    }

    #[test]
    fn guard_rejects_secret_writes_when_env_backend_is_vault() {
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Secrets,
            crate::defaults::VAULT_SECRETS_PACK,
        ));
        let td = tempdir().unwrap();
        let err =
            check_applyable_manifest(&env, td.path(), &secrets_manifest(), false).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(m) if m.contains("non-dev-store backend")));
    }

    #[test]
    fn guard_rejects_a_plan_target_that_repoints_the_update_channel() {
        // A signed plan whose target re-points `plan_endpoint` would control
        // every plan that follows it. Refused before anything is applied.
        let env = make_env("local");
        let td = tempdir().unwrap();
        let m = parse_manifest(json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": "local"},
            "updates": {"plan_endpoint": "https://attacker.example.com/plan"}
        }));
        let err = check_applyable_manifest(&env, td.path(), &m, false).unwrap_err();
        assert!(
            matches!(err, OpError::InvalidArgument(msg) if msg.contains("re-point the update channel")),
            "unexpected error"
        );
    }

    #[test]
    fn guard_rejects_a_plan_target_that_repoints_the_trust_root() {
        // A signed plan whose target re-points the trust root would gain
        // permanent signing authority. Refused before anything is applied.
        let env = make_env("local");
        let td = tempdir().unwrap();
        let m = parse_manifest(json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": "local"},
            "trust_root": "bootstrap"
        }));
        let err = check_applyable_manifest(&env, td.path(), &m, false).unwrap_err();
        assert!(
            matches!(err, OpError::InvalidArgument(msg) if msg.contains("re-point the trust root")),
            "unexpected error"
        );
    }

    #[test]
    fn guard_accepts_a_plan_target_without_an_updates_block() {
        // The shape `op updates publish` produces: the block is stripped at sign
        // time, so an ordinary content plan applies.
        let env = make_env("local");
        let td = tempdir().unwrap();
        let m = parse_manifest(json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": "local"}
        }));
        check_applyable_manifest(&env, td.path(), &m, false).unwrap();
    }

    #[test]
    fn guard_rejects_secret_writes_when_manifest_rebinds_secrets_off_dev_store() {
        // Env is dev-store, but the manifest rebinds Secrets → Vault; env_apply
        // applies packs[] before secrets[], so the write escapes the snapshot.
        let env = make_env("local");
        let td = tempdir().unwrap();
        let m = parse_manifest(json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": "local"},
            "packs": [{"slot": "secrets", "kind": "greentic.secrets.vault@1.0.0", "pack_ref": "vault"}],
            "secrets": [{"path": "acme/_/tls/foo", "from_env": "FOO"}]
        }));
        let err = check_applyable_manifest(&env, td.path(), &m, false).unwrap_err();
        assert!(
            matches!(err, OpError::InvalidArgument(msg) if msg.contains("rebinds the Secrets slot"))
        );
    }

    #[test]
    fn guard_accepts_manifest_rebinding_secrets_to_dev_store() {
        // A same-family (dev-store) rebind is not an escape — the sink stays
        // snapshotted.
        let env = make_env("local");
        let td = tempdir().unwrap();
        let m = parse_manifest(json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": "local"},
            "packs": [{"slot": "secrets", "kind": "greentic.secrets.dev-store@1.0.0", "pack_ref": "local"}],
            "secrets": [{"path": "acme/_/tls/foo", "from_env": "FOO"}]
        }));
        check_applyable_manifest(&env, td.path(), &m, false).unwrap();
    }

    #[test]
    fn guard_rejects_secret_writes_under_dev_secrets_path_override() {
        // GREENTIC_DEV_SECRETS_PATH redirects the dev-store off the env tree; the
        // snapshot can't reach it, so secret writes are refused. Passed as a bool
        // because the multithreaded harness cannot set process env vars safely.
        let env = make_env("local");
        let td = tempdir().unwrap();
        let err = check_applyable_manifest(&env, td.path(), &secrets_manifest(), true).unwrap_err();
        assert!(
            matches!(err, OpError::InvalidArgument(m) if m.contains("GREENTIC_DEV_SECRETS_PATH"))
        );
    }

    #[test]
    fn guard_rejects_secret_writes_when_dev_store_file_is_symlinked() {
        // A pre-existing symlink where the dev-store file resolves escapes the
        // snapshot's rollback (capture follows it; restore's rename-over replaces
        // the link, leaving the external target's written secret in place).
        use std::os::unix::fs::symlink;
        let env = make_env("local");
        let td = tempdir().unwrap();
        let dev = td.path().join(crate::cli::secrets::DEV_STORE_RELATIVE);
        std::fs::create_dir_all(dev.parent().unwrap()).unwrap();
        let external = td.path().join("external.env");
        std::fs::write(&external, b"x").unwrap();
        symlink(&external, &dev).unwrap();
        let err =
            check_applyable_manifest(&env, td.path(), &secrets_manifest(), false).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(m) if m.contains("symlink")));
    }

    #[test]
    fn guard_ignores_sink_when_manifest_writes_no_secrets() {
        // The sink guard fires only for secrets[]/messaging_endpoints[]. A pinned
        // bundle on a Vault-backed env is applyable — it writes no dev-store
        // secret material.
        let mut env = make_env("local");
        env.packs.push(make_binding(
            CapabilitySlot::Secrets,
            crate::defaults::VAULT_SECRETS_PACK,
        ));
        let td = tempdir().unwrap();
        let m = parse_manifest(json!({
            "schema": "greentic.env-manifest.v1",
            "environment": {"id": "local"},
            "bundles": [{"bundle_id": "b1", "bundle_path": "/x.gtbundle", "bundle_digest": "sha256:aa"}]
        }));
        check_applyable_manifest(&env, td.path(), &m, false).unwrap();
    }

    // ---- Phase 3.1: op updates recover ------------------------------------

    #[test]
    fn recover_schema_only_returns_payload_schema() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let out = recover_updates(
            &store,
            &OpFlags {
                schema_only: true,
                ..OpFlags::default()
            },
            None,
            false,
        )
        .unwrap();
        assert_eq!(out.op, "recover");
        assert_eq!(out.noun, NOUN);
        assert!(out.result["properties"]["plan_id"].is_object());
    }

    #[test]
    fn recover_plan_not_found_is_not_found() {
        let dir = tempdir().unwrap();
        let updates_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (_priv7, tk7) = key_pair(7);
        env_trusting(&store, &tk7);
        let err = recover_updates_impl(
            &store,
            &OpFlags::default(),
            Some(RecoverUpdatesPayload {
                environment_id: "local".into(),
                plan_id: "ghost".into(),
            }),
            true,
            Some(updates_dir.path()),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::NotFound(_)));
    }

    #[test]
    fn recover_forces_applying_to_failed_and_audits() {
        use greentic_update::staging::{UpdateStage, UpdatesRoot};
        let dir = tempdir().unwrap();
        let updates_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (priv7, tk7) = key_pair(7);
        let env_id = env_trusting(&store, &tk7);
        stage_local(updates_dir.path(), "plan-1", 1, &priv7, &tk7);
        // Strand the plan in `applying`, as a crashed applier would leave it.
        UpdatesRoot::open_in(updates_dir.path(), "local")
            .unwrap()
            .load("plan-1")
            .unwrap()
            .unwrap()
            .transition(UpdateStage::Applying)
            .unwrap();

        let out = recover_updates_impl(
            &store,
            &OpFlags::default(),
            Some(RecoverUpdatesPayload {
                environment_id: "local".into(),
                plan_id: "plan-1".into(),
            }),
            true,
            Some(updates_dir.path()),
        )
        .unwrap();

        assert_eq!(out.op, "recover");
        assert_eq!(out.result["previous_stage"], "applying");
        assert_eq!(out.result["stage"], "failed");
        assert!(out.result["applying_since"].as_str().is_some());

        // On-disk FSM marker was force-failed.
        assert_eq!(
            on_disk_stage(updates_dir.path(), "plan-1"),
            UpdateStage::Failed
        );
        // The recovery was recorded in the deployer audit ledger.
        let env_dir = store.env_dir(&env_id).unwrap();
        let audit = std::fs::read_to_string(env_dir.join("audit").join("events.jsonl")).unwrap();
        assert!(
            audit.contains("recover") && audit.contains("plan-1"),
            "audit must record the recover: {audit}"
        );
    }

    #[test]
    fn recover_refuses_without_force() {
        use greentic_update::staging::{UpdateStage, UpdatesRoot};
        let dir = tempdir().unwrap();
        let updates_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (priv7, tk7) = key_pair(7);
        env_trusting(&store, &tk7);
        stage_local(updates_dir.path(), "plan-1", 1, &priv7, &tk7);
        UpdatesRoot::open_in(updates_dir.path(), "local")
            .unwrap()
            .load("plan-1")
            .unwrap()
            .unwrap()
            .transition(UpdateStage::Applying)
            .unwrap();

        let err = recover_updates_impl(
            &store,
            &OpFlags::default(),
            Some(RecoverUpdatesPayload {
                environment_id: "local".into(),
                plan_id: "plan-1".into(),
            }),
            false,
            Some(updates_dir.path()),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(m) if m.contains("--force")));
        // Fail-closed: the plan is untouched — still Applying.
        assert_eq!(
            on_disk_stage(updates_dir.path(), "plan-1"),
            UpdateStage::Applying
        );
    }

    #[test]
    fn recover_rejects_staged_plan() {
        use greentic_update::staging::UpdateStage;
        let dir = tempdir().unwrap();
        let updates_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (priv7, tk7) = key_pair(7);
        env_trusting(&store, &tk7);
        stage_local(updates_dir.path(), "plan-1", 1, &priv7, &tk7);

        let err = recover_updates_impl(
            &store,
            &OpFlags::default(),
            Some(RecoverUpdatesPayload {
                environment_id: "local".into(),
                plan_id: "plan-1".into(),
            }),
            true,
            Some(updates_dir.path()),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(m) if m.contains("not `applying`")));
        assert_eq!(
            on_disk_stage(updates_dir.path(), "plan-1"),
            UpdateStage::Staged
        );
    }

    #[test]
    fn recover_rejects_terminal_plan() {
        use greentic_update::staging::UpdateStage;
        let dir = tempdir().unwrap();
        let updates_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (priv7, tk7) = key_pair(7);
        env_trusting(&store, &tk7);
        stage_local(updates_dir.path(), "plan-1", 1, &priv7, &tk7);
        // Apply to completion ⇒ terminal `applied`.
        apply_updates_impl(
            &store,
            &OpFlags::default(),
            Some(ApplyUpdatesPayload {
                environment_id: "local".into(),
                plan_id: "plan-1".into(),
            }),
            Some(updates_dir.path()),
        )
        .unwrap();

        let err = recover_updates_impl(
            &store,
            &OpFlags::default(),
            Some(RecoverUpdatesPayload {
                environment_id: "local".into(),
                plan_id: "plan-1".into(),
            }),
            true,
            Some(updates_dir.path()),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(m) if m.contains("terminal")));
        assert_eq!(
            on_disk_stage(updates_dir.path(), "plan-1"),
            UpdateStage::Applied
        );
    }

    // ---- plan-build -------------------------------------------------------

    /// Write an ephemeral PKCS#8 Ed25519 private key PEM to `dir/key.pem` and
    /// return (path, TrustedKey) so callers can seed the env trust root and pass
    /// `--signing-key`.
    fn write_ephemeral_key(dir: &std::path::Path) -> (PathBuf, TrustedKey) {
        let (priv_pem, tk) = key_pair(42);
        let key_path = dir.join("key.pem");
        std::fs::write(&key_path, &priv_pem).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        (key_path, tk)
    }

    fn plan_build_args(
        env_id: &str,
        sequence: u64,
        binaries: Vec<String>,
        signing_key: Option<PathBuf>,
        out_dir: PathBuf,
    ) -> crate::cli::dispatch::UpdatesPlanBuildArgs {
        crate::cli::dispatch::UpdatesPlanBuildArgs {
            env_id: Some(env_id.to_string()),
            sequence: Some(sequence),
            binaries,
            signing_key,
            target_file: None,
            min_runtime: None,
            out_dir: Some(out_dir),
            release: None,
            release_repo: None,
            release_binary_name: None,
            targets: vec![],
            expected_target_count: None,
            trust_root: None,
        }
    }

    #[test]
    fn parse_binary_spec_happy_path() {
        let spec = "name=greentic-start,version=1.1.9,target=x86_64-unknown-linux-gnu,digest=sha256:abc123";
        let ba = parse_binary_spec(spec).unwrap();
        assert_eq!(ba.name, "greentic-start");
        assert_eq!(ba.version, "1.1.9");
        assert_eq!(ba.target, "x86_64-unknown-linux-gnu");
        assert_eq!(ba.digest, "sha256:abc123");
        assert_eq!(ba.source, None);
    }

    #[test]
    fn parse_binary_spec_with_source() {
        let spec = "name=greentic-start,version=1.1.9,target=x86_64-unknown-linux-gnu,digest=sha256:abc,source=https://example.com/bin.tar.gz";
        let ba = parse_binary_spec(spec).unwrap();
        assert_eq!(ba.source.as_deref(), Some("https://example.com/bin.tar.gz"));
    }

    #[test]
    fn parse_binary_spec_missing_required_key() {
        // Missing `digest`.
        let spec = "name=greentic-start,version=1.1.9,target=x86_64-unknown-linux-gnu";
        let err = parse_binary_spec(spec).unwrap_err();
        match err {
            OpError::InvalidArgument(msg) => assert!(
                msg.contains("digest"),
                "error should name the missing key `digest`, got: {msg}"
            ),
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn parse_binary_spec_unknown_key() {
        let spec = "name=x,version=1,target=t,digest=d,flavor=sweet";
        let err = parse_binary_spec(spec).unwrap_err();
        match err {
            OpError::InvalidArgument(msg) => assert!(
                msg.contains("flavor"),
                "error should name the unknown key `flavor`, got: {msg}"
            ),
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn parse_binary_spec_source_omitted_is_none() {
        let spec = "name=x,version=1,target=t,digest=d";
        let ba = parse_binary_spec(spec).unwrap();
        assert!(ba.source.is_none());
    }

    #[test]
    fn plan_build_round_trip_verifies() {
        let dir = tempdir().unwrap();
        let out_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (key_path, tk) = write_ephemeral_key(dir.path());
        env_trusting(&store, &tk);

        let args = plan_build_args(
            "local",
            1,
            vec![
                "name=greentic-start,version=1.1.9,target=x86_64-unknown-linux-gnu,digest=sha256:deadbeef,source=https://example.com/bin.tar.gz".to_string(),
            ],
            Some(key_path),
            out_dir.path().to_path_buf(),
        );
        let outcome = plan_build(&store, &OpFlags::default(), args).unwrap();
        assert_eq!(outcome.noun, NOUN);
        assert_eq!(outcome.op, "plan-build");

        // Read the emitted files and verify against the env trust root.
        let plan_bytes = std::fs::read(out_dir.path().join("plan.json")).unwrap();
        let sig_bytes = std::fs::read(out_dir.path().join("plan.json.sig")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        let trust = store_trust_root::load(&env_dir).unwrap();
        let verified =
            greentic_update::plan::verify_update_plan(&plan_bytes, &sig_bytes, &trust).unwrap();

        // The decoded plan binaries must match the input spec.
        assert_eq!(verified.plan.binaries.len(), 1);
        let b = &verified.plan.binaries[0];
        assert_eq!(b.name, "greentic-start");
        assert_eq!(b.version, "1.1.9");
        assert_eq!(b.target, "x86_64-unknown-linux-gnu");
        assert_eq!(b.digest, "sha256:deadbeef");
        assert_eq!(b.source.as_deref(), Some("https://example.com/bin.tar.gz"));

        // Content artifacts are empty (plan-build is binary-only).
        assert!(verified.plan.artifacts.is_empty());
        // Sequence matches.
        assert_eq!(verified.plan.sequence, 1);
    }

    #[test]
    fn plan_build_fail_closed_untrusted_key() {
        let dir = tempdir().unwrap();
        let out_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        // Trust key 7, but sign with key 42.
        let (_priv7, tk7) = key_pair(7);
        env_trusting(&store, &tk7);
        let (key_path_42, _tk42) = write_ephemeral_key(dir.path());

        let args = plan_build_args(
            "local",
            1,
            vec!["name=x,version=1,target=t,digest=d".to_string()],
            Some(key_path_42),
            out_dir.path().to_path_buf(),
        );
        let err = plan_build(&store, &OpFlags::default(), args).unwrap_err();
        assert!(
            matches!(err, OpError::Conflict(_)),
            "expected Conflict for untrusted key, got {err:?}"
        );
        // No files written.
        assert!(!out_dir.path().join("plan.json").exists());
    }

    #[test]
    fn plan_build_min_runtime_threaded_through() {
        let dir = tempdir().unwrap();
        let out_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (key_path, tk) = write_ephemeral_key(dir.path());
        env_trusting(&store, &tk);

        let mut args = plan_build_args(
            "local",
            1,
            vec!["name=x,version=1,target=t,digest=d".to_string()],
            Some(key_path),
            out_dir.path().to_path_buf(),
        );
        args.min_runtime = Some("1.1.5".to_string());
        let _outcome = plan_build(&store, &OpFlags::default(), args).unwrap();

        let plan_bytes = std::fs::read(out_dir.path().join("plan.json")).unwrap();
        let sig_bytes = std::fs::read(out_dir.path().join("plan.json.sig")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        let trust = store_trust_root::load(&env_dir).unwrap();
        let verified =
            greentic_update::plan::verify_update_plan(&plan_bytes, &sig_bytes, &trust).unwrap();
        assert_eq!(verified.plan.compat.min_runtime.as_deref(), Some("1.1.5"));
    }

    #[test]
    fn plan_build_target_file_threaded_through() {
        let dir = tempdir().unwrap();
        let out_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (key_path, tk) = write_ephemeral_key(dir.path());
        env_trusting(&store, &tk);

        let target_file = dir.path().join("target.json");
        std::fs::write(
            &target_file,
            r#"{"schema":"greentic.env-manifest.v1","environment":{"id":"local"}}"#,
        )
        .unwrap();

        let mut args = plan_build_args(
            "local",
            1,
            vec!["name=x,version=1,target=t,digest=d".to_string()],
            Some(key_path),
            out_dir.path().to_path_buf(),
        );
        args.target_file = Some(target_file);
        let _outcome = plan_build(&store, &OpFlags::default(), args).unwrap();

        let plan_bytes = std::fs::read(out_dir.path().join("plan.json")).unwrap();
        let sig_bytes = std::fs::read(out_dir.path().join("plan.json.sig")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        let trust = store_trust_root::load(&env_dir).unwrap();
        let verified =
            greentic_update::plan::verify_update_plan(&plan_bytes, &sig_bytes, &trust).unwrap();
        assert_eq!(
            verified.plan.target["environment"]["id"].as_str(),
            Some("local")
        );
    }

    #[test]
    fn plan_build_content_only_plan_verifies() {
        let dir = tempdir().unwrap();
        let out_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (key_path, tk) = write_ephemeral_key(dir.path());
        env_trusting(&store, &tk);

        let target_file = dir.path().join("target.json");
        std::fs::write(
            &target_file,
            r#"{"schema":"greentic.env-manifest.v1","environment":{"id":"local"},
                "bundles":[{"bundle_id":"app","bundle_path":"/tmp/app.gtbundle","bundle_digest":"sha256:aa"}]}"#,
        )
        .unwrap();

        // No --binary at all: a content-only plan is the ordinary env-update case.
        let mut args = plan_build_args(
            "local",
            2,
            vec![],
            Some(key_path),
            out_dir.path().to_path_buf(),
        );
        args.target_file = Some(target_file);
        plan_build(&store, &OpFlags::default(), args).unwrap();

        let plan_bytes = std::fs::read(out_dir.path().join("plan.json")).unwrap();
        let sig_bytes = std::fs::read(out_dir.path().join("plan.json.sig")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        let trust = store_trust_root::load(&env_dir).unwrap();
        let verified =
            greentic_update::plan::verify_update_plan(&plan_bytes, &sig_bytes, &trust).unwrap();
        assert!(verified.plan.binaries.is_empty());
        assert_eq!(
            verified.plan.target["bundles"][0]["bundle_id"].as_str(),
            Some("app")
        );
    }

    fn publish_args(env_id: &str) -> crate::cli::dispatch::UpdatesPublishArgs {
        crate::cli::dispatch::UpdatesPublishArgs {
            env_id: Some(env_id.to_string()),
            target_file: None,
            sequence: None,
            binaries: vec![],
            signing_key: None,
            min_runtime: None,
            plan_endpoint: None,
            upload_token: None,
            release: None,
            release_repo: None,
            release_binary_name: None,
            targets: vec![],
            expected_target_count: None,
            trust_root: None,
            all_envs: false,
            plan_server_url: None,
        }
    }

    /// Write a content target and return its path.
    fn content_target(dir: &Path) -> PathBuf {
        let target_file = dir.join("target.json");
        std::fs::write(
            &target_file,
            r#"{"schema":"greentic.env-manifest.v1","environment":{"id":"local"},
                "bundles":[{"bundle_id":"app","bundle_path":"/tmp/app.gtbundle","bundle_digest":"sha256:aa"}]}"#,
        )
        .unwrap();
        target_file
    }

    #[test]
    fn publish_without_a_plan_endpoint_fails_before_signing() {
        // Resolution order matters: an env with no configured endpoint must fail
        // fast, not mint a plan and burn a sequence number first.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (_key_path, tk) = write_ephemeral_key(dir.path());
        env_trusting(&store, &tk);

        let mut args = publish_args("local");
        args.target_file = Some(content_target(dir.path()));
        args.upload_token = Some("token".to_string());
        let err = publish(&store, &OpFlags::default(), args).unwrap_err();
        assert!(
            matches!(&err, OpError::InvalidArgument(m) if m.contains("plan_endpoint")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn publish_rejects_an_unacceptable_plan_endpoint() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (_key_path, tk) = write_ephemeral_key(dir.path());
        env_trusting(&store, &tk);

        let mut args = publish_args("local");
        args.target_file = Some(content_target(dir.path()));
        args.upload_token = Some("token".to_string());
        args.plan_endpoint = Some("http://updates.example.com/plan".to_string());
        let err = publish(&store, &OpFlags::default(), args).unwrap_err();
        assert!(
            matches!(&err, OpError::InvalidArgument(m) if m.contains("control URL")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn publish_defaults_its_endpoint_to_the_envs_subscription() {
        // The env's own `plan_endpoint` decides where its updates are published,
        // so `op updates publish <env> --target-file f.json` needs no URL. Proven
        // by pointing the channel at a closed loopback port: resolution and
        // signing succeed, and the run dies at the upload with a fetch error
        // naming that endpoint.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (key_path, tk) = write_ephemeral_key(dir.path());
        let env_id = env_trusting(&store, &tk);

        let endpoint = "http://127.0.0.1:1/v1/environments/local/plan";
        config_set(
            &store,
            &OpFlags::default(),
            Some(UpdateConfigSetPayload {
                environment_id: env_id.as_str().to_string(),
                enabled: Some(true),
                on_notify: Some("apply".into()),
                poll_interval_secs: None,
                plan_endpoint: Some(endpoint.to_string()),
                push_enabled: None,
                stream_endpoint: None,
            }),
        )
        .unwrap();

        let mut args = publish_args("local");
        args.target_file = Some(content_target(dir.path()));
        args.upload_token = Some("token".to_string());
        args.signing_key = Some(key_path);
        args.sequence = Some(2); // skip the /meta round-trip
        let err = publish(&store, &OpFlags::default(), args).unwrap_err();
        assert!(
            matches!(&err, OpError::Fetch(m) if m.contains("127.0.0.1:1")),
            "expected an upload fetch failure against the configured endpoint, got: {err:?}"
        );
    }

    #[test]
    fn publish_schema_only_describes_its_args() {
        let out = publish(
            &LocalFsStore::new(tempdir().unwrap().path()),
            &OpFlags {
                schema_only: true,
                answers: None,
            },
            publish_args("local"),
        )
        .unwrap();
        assert_eq!(out.result["title"], json!("UpdatesPublishArgs"));
        // env_id is no longer required at schema level (optional with --all-envs).
        assert!(out.result["properties"]["env_id"].is_object());
    }

    #[test]
    fn plan_build_strips_an_updates_block_from_the_signed_target() {
        // Same manifest an operator hands `op env apply` — it declares the
        // subscription. The signed plan must not carry it: a plan that re-points
        // `plan_endpoint` would control every plan that follows it. Stripped here,
        // and `check_applyable_manifest` refuses it if a plan built any other way
        // still carries one.
        let dir = tempdir().unwrap();
        let out_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (key_path, tk) = write_ephemeral_key(dir.path());
        env_trusting(&store, &tk);

        let target_file = dir.path().join("target.json");
        std::fs::write(
            &target_file,
            r#"{"schema":"greentic.env-manifest.v1","environment":{"id":"local"},
                "updates":{"plan_endpoint":"https://attacker.example.com/plan"},
                "bundles":[{"bundle_id":"app","bundle_path":"/tmp/app.gtbundle","bundle_digest":"sha256:aa"}]}"#,
        )
        .unwrap();

        let mut args = plan_build_args(
            "local",
            2,
            vec![],
            Some(key_path),
            out_dir.path().to_path_buf(),
        );
        args.target_file = Some(target_file);
        let outcome = plan_build(&store, &OpFlags::default(), args).unwrap();
        assert_eq!(outcome.result["stripped_updates_block"], json!(true));
        assert_eq!(outcome.result["stripped_trust_root"], json!(false));

        let plan_bytes = std::fs::read(out_dir.path().join("plan.json")).unwrap();
        let sig_bytes = std::fs::read(out_dir.path().join("plan.json.sig")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        let trust = store_trust_root::load(&env_dir).unwrap();
        let verified =
            greentic_update::plan::verify_update_plan(&plan_bytes, &sig_bytes, &trust).unwrap();
        assert!(
            verified.plan.target.get("updates").is_none(),
            "the signed target still carries an `updates` block"
        );
        // The rest of the manifest is untouched.
        assert_eq!(
            verified.plan.target["bundles"][0]["bundle_id"].as_str(),
            Some("app")
        );
    }

    #[test]
    fn plan_build_strips_a_trust_root_block_from_the_signed_target() {
        let dir = tempdir().unwrap();
        let out_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (key_path, tk) = write_ephemeral_key(dir.path());
        env_trusting(&store, &tk);

        let target_file = dir.path().join("target.json");
        std::fs::write(
            &target_file,
            r#"{"schema":"greentic.env-manifest.v1","environment":{"id":"local"},
                "trust_root":"bootstrap",
                "bundles":[{"bundle_id":"app","bundle_path":"/tmp/app.gtbundle","bundle_digest":"sha256:aa"}]}"#,
        )
        .unwrap();

        let mut args = plan_build_args(
            "local",
            2,
            vec![],
            Some(key_path),
            out_dir.path().to_path_buf(),
        );
        args.target_file = Some(target_file);
        let outcome = plan_build(&store, &OpFlags::default(), args).unwrap();
        assert_eq!(outcome.result["stripped_trust_root"], json!(true));
        assert_eq!(outcome.result["stripped_updates_block"], json!(false));

        let plan_bytes = std::fs::read(out_dir.path().join("plan.json")).unwrap();
        let sig_bytes = std::fs::read(out_dir.path().join("plan.json.sig")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        let trust = store_trust_root::load(&env_dir).unwrap();
        let verified =
            greentic_update::plan::verify_update_plan(&plan_bytes, &sig_bytes, &trust).unwrap();
        assert!(
            verified.plan.target.get("trust_root").is_none(),
            "the signed target still carries a `trust_root` block"
        );
        assert_eq!(
            verified.plan.target["bundles"][0]["bundle_id"].as_str(),
            Some("app")
        );
    }

    /// `plan-build` with `target_json` as the target, returning the result.
    fn plan_build_with_target(
        dir: &Path,
        out_dir: &Path,
        target_json: &str,
    ) -> Result<(), OpError> {
        let store = LocalFsStore::new(dir);
        let (key_path, tk) = write_ephemeral_key(dir);
        env_trusting(&store, &tk);
        let target_file = dir.join("target.json");
        std::fs::write(&target_file, target_json).unwrap();
        let mut args = plan_build_args("local", 1, vec![], Some(key_path), out_dir.to_path_buf());
        args.target_file = Some(target_file);
        plan_build(&store, &OpFlags::default(), args).map(|_| ())
    }

    #[test]
    fn plan_build_rejects_a_target_that_is_not_an_env_manifest() {
        // `publish` uploads straight to the live channel and burns a sequence, so
        // a target every client is going to reject must never get that far.
        let dir = tempdir().unwrap();
        let out = tempdir().unwrap();
        let err =
            plan_build_with_target(dir.path(), out.path(), r#"{"hello":"world"}"#).unwrap_err();
        assert!(
            matches!(&err, OpError::InvalidArgument(m) if m.contains("not a valid")),
            "unexpected error: {err:?}"
        );
        assert!(
            !out.path().join("plan.json").exists(),
            "a rejected target must not leave a signed plan behind"
        );
    }

    #[test]
    fn plan_build_rejects_a_target_that_fails_shape_validation() {
        let dir = tempdir().unwrap();
        let out = tempdir().unwrap();
        let err = plan_build_with_target(
            dir.path(),
            out.path(),
            r#"{"schema":"greentic.env-manifest.v2","environment":{"id":"local"}}"#,
        )
        .unwrap_err();
        assert!(
            matches!(&err, OpError::InvalidArgument(m) if m.contains("schema")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn plan_build_rejects_a_target_addressed_to_another_environment() {
        // The consumer cross-checks `manifest.environment.id` against the plan's
        // env id and refuses. Catch the misaddressed target at sign time.
        let dir = tempdir().unwrap();
        let out = tempdir().unwrap();
        let err = plan_build_with_target(
            dir.path(),
            out.path(),
            r#"{"schema":"greentic.env-manifest.v1","environment":{"id":"staging"}}"#,
        )
        .unwrap_err();
        assert!(
            matches!(&err, OpError::InvalidArgument(m)
                if m.contains("staging") && m.contains("local")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn plan_build_validates_the_target_after_the_updates_strip() {
        // The `updates` block is not part of `EnvManifest`'s applyable shape as
        // far as a plan is concerned, and it is stripped — so a target carrying
        // one must still validate. (It parses either way; this pins the ordering
        // so a future `deny`-style check cannot fire on a field we just removed.)
        let dir = tempdir().unwrap();
        let out = tempdir().unwrap();
        plan_build_with_target(
            dir.path(),
            out.path(),
            r#"{"schema":"greentic.env-manifest.v1","environment":{"id":"local"},
                "updates":{"plan_endpoint":"https://u.example.com/plan"}}"#,
        )
        .expect("a stripped target validates");
        assert!(out.path().join("plan.json").exists());
    }

    #[test]
    fn publish_rejects_a_bad_target_before_burning_a_sequence() {
        // Ordering guarantee: the target is validated during signing, which runs
        // before the upload. A misaddressed target must fail without the plan
        // server ever being contacted — the endpoint here is a closed port, and a
        // Fetch error would mean we got as far as the upload.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (key_path, tk) = write_ephemeral_key(dir.path());
        env_trusting(&store, &tk);

        let target_file = dir.path().join("target.json");
        std::fs::write(
            &target_file,
            r#"{"schema":"greentic.env-manifest.v1","environment":{"id":"staging"}}"#,
        )
        .unwrap();

        let mut args = publish_args("local");
        args.target_file = Some(target_file);
        args.upload_token = Some("token".to_string());
        args.signing_key = Some(key_path);
        args.sequence = Some(2);
        args.plan_endpoint = Some("http://127.0.0.1:1/v1/environments/local/plan".to_string());
        let err = publish(&store, &OpFlags::default(), args).unwrap_err();
        assert!(
            matches!(&err, OpError::InvalidArgument(m) if m.contains("staging")),
            "expected the target to be rejected before the upload, got: {err:?}"
        );
    }

    #[test]
    fn strip_non_applyable_blocks_reports_whether_each_was_present() {
        let mut with = json!({"schema": "x", "updates": {"plan_endpoint": "https://u/p"}});
        let s = strip_non_applyable_blocks(&mut with);
        assert!(s.updates);
        assert!(!s.trust_root);
        assert!(with.get("updates").is_none());
        assert_eq!(with["schema"], json!("x"));

        let mut without = json!({"schema": "x"});
        let s = strip_non_applyable_blocks(&mut without);
        assert!(!s.updates);
        assert!(!s.trust_root);

        // A non-object target (never produced here, but the helper must not panic).
        let mut scalar = json!("not-an-object");
        let s = strip_non_applyable_blocks(&mut scalar);
        assert!(!s.updates);
        assert!(!s.trust_root);
    }

    #[test]
    fn strip_non_applyable_blocks_removes_trust_root() {
        let mut target = json!({"schema": "x", "trust_root": "bootstrap"});
        let s = strip_non_applyable_blocks(&mut target);
        assert!(s.trust_root);
        assert!(!s.updates);
        assert!(target.get("trust_root").is_none());
        assert_eq!(target["schema"], json!("x"));
    }

    #[test]
    fn strip_non_applyable_blocks_removes_both_updates_and_trust_root() {
        let mut target = json!({
            "schema": "x",
            "updates": {"plan_endpoint": "https://u/p"},
            "trust_root": "bootstrap"
        });
        let s = strip_non_applyable_blocks(&mut target);
        assert!(s.updates);
        assert!(s.trust_root);
        assert!(target.get("updates").is_none());
        assert!(target.get("trust_root").is_none());
        assert_eq!(target["schema"], json!("x"));
    }

    #[test]
    fn strip_non_applyable_blocks_leaves_clean_manifest_unchanged() {
        let mut target = json!({
            "schema": "x",
            "environment": {"id": "local"},
            "bundles": [{"bundle_id": "app"}]
        });
        let original = target.clone();
        let s = strip_non_applyable_blocks(&mut target);
        assert!(!s.updates);
        assert!(!s.trust_root);
        assert_eq!(target, original);
    }

    #[test]
    fn plan_build_rejects_plan_with_neither_target_nor_binary() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (key_path, tk) = write_ephemeral_key(dir.path());
        env_trusting(&store, &tk);

        let args = plan_build_args("local", 1, vec![], Some(key_path), dir.path().to_path_buf());
        let err = plan_build(&store, &OpFlags::default(), args).unwrap_err();
        assert!(
            matches!(&err, OpError::InvalidArgument(m) if m.contains("--binary") && m.contains("--target-file")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn plan_build_schema_only() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let args = plan_build_args(
            "local",
            1,
            vec!["name=x,version=1,target=t,digest=d".to_string()],
            None,
            dir.path().to_path_buf(),
        );
        let out = plan_build(
            &store,
            &OpFlags {
                schema_only: true,
                ..OpFlags::default()
            },
            args,
        )
        .unwrap();
        assert_eq!(out.op, "plan-build");
        assert_eq!(out.noun, NOUN);
        assert!(out.result["properties"]["sequence"].is_object());
    }

    // ---- --release / --trust-root / --all-envs tests -------------------------

    #[test]
    fn release_and_binary_conflict_rejected_by_clap() {
        use clap::Parser;

        #[derive(Parser)]
        struct Cli {
            #[command(subcommand)]
            cmd: Cmd,
        }
        #[derive(clap::Subcommand)]
        enum Cmd {
            PlanBuild(crate::cli::dispatch::UpdatesPlanBuildArgs),
        }

        let result = Cli::try_parse_from([
            "test",
            "plan-build",
            "local",
            "--sequence",
            "1",
            "--binary",
            "name=x,version=1,target=t,digest=d",
            "--release",
            "1.1.12",
        ]);
        assert!(
            result.is_err(),
            "clap should reject --release combined with --binary"
        );
    }

    #[test]
    fn trust_root_override_plan_build() {
        let dir = tempdir().unwrap();
        let out_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (key_path, tk) = write_ephemeral_key(dir.path());

        // Create env WITHOUT seeding its trust root.
        store.save(&make_env("local")).unwrap();

        // Write trust-root.json to a separate location.
        let trust_root_dir = tempdir().unwrap();
        let trust_root_path = trust_root_dir.path().join("trust-root.json");
        let trust_doc =
            greentic_operator_trust::trust_root::TrustRootDocument::v1(vec![tk.clone()]);
        std::fs::write(
            &trust_root_path,
            serde_json::to_string_pretty(&trust_doc).unwrap(),
        )
        .unwrap();

        let mut args = plan_build_args(
            "local",
            1,
            vec!["name=x,version=1,target=t,digest=sha256:aabb".to_string()],
            Some(key_path),
            out_dir.path().to_path_buf(),
        );
        args.trust_root = Some(trust_root_path);

        let outcome = plan_build(&store, &OpFlags::default(), args).unwrap();
        assert_eq!(outcome.op, "plan-build");

        // Verify the emitted plan round-trips against the same trust root.
        let plan_bytes = std::fs::read(out_dir.path().join("plan.json")).unwrap();
        let sig_bytes = std::fs::read(out_dir.path().join("plan.json.sig")).unwrap();
        let trust = greentic_distributor_client::signing::TrustRoot::new(vec![tk]);
        let verified =
            greentic_update::plan::verify_update_plan(&plan_bytes, &sig_bytes, &trust).unwrap();
        assert_eq!(verified.plan.binaries.len(), 1);
    }

    #[test]
    fn trust_root_override_fails_with_wrong_key() {
        let dir = tempdir().unwrap();
        let out_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (key_path_42, _tk42) = write_ephemeral_key(dir.path());

        store.save(&make_env("local")).unwrap();

        // Trust root trusts key 7, signing with key 42.
        let (_priv7, tk7) = key_pair(7);
        let trust_root_dir = tempdir().unwrap();
        let trust_root_path = trust_root_dir.path().join("trust-root.json");
        let trust_doc = greentic_operator_trust::trust_root::TrustRootDocument::v1(vec![tk7]);
        std::fs::write(
            &trust_root_path,
            serde_json::to_string_pretty(&trust_doc).unwrap(),
        )
        .unwrap();

        let mut args = plan_build_args(
            "local",
            1,
            vec!["name=x,version=1,target=t,digest=d".to_string()],
            Some(key_path_42),
            out_dir.path().to_path_buf(),
        );
        args.trust_root = Some(trust_root_path);

        let err = plan_build(&store, &OpFlags::default(), args).unwrap_err();
        assert!(
            matches!(err, OpError::Conflict(_)),
            "expected Conflict for untrusted key, got {err:?}"
        );
    }

    #[test]
    fn publish_schema_includes_release_fields() {
        let schema = publish_schema();
        let props = &schema["properties"];
        assert!(props["release"].is_object(), "missing release");
        assert!(props["release_repo"].is_object(), "missing release_repo");
        assert!(
            props["release_binary_name"].is_object(),
            "missing release_binary_name"
        );
        assert!(props["targets"].is_object(), "missing targets");
        assert!(props["trust_root"].is_object(), "missing trust_root");
        assert!(props["all_envs"].is_object(), "missing all_envs");
        assert!(
            props["plan_server_url"].is_object(),
            "missing plan_server_url"
        );
    }

    #[test]
    fn plan_build_schema_includes_release_fields() {
        let schema = plan_build_schema();
        let props = &schema["properties"];
        assert!(props["release"].is_object(), "missing release");
        assert!(props["release_repo"].is_object(), "missing release_repo");
        assert!(
            props["release_binary_name"].is_object(),
            "missing release_binary_name"
        );
        assert!(props["targets"].is_object(), "missing targets");
        assert!(props["trust_root"].is_object(), "missing trust_root");
    }

    #[test]
    fn publish_requires_content_or_release() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (_key_path, tk) = write_ephemeral_key(dir.path());
        env_trusting(&store, &tk);

        let mut args = publish_args("local");
        args.upload_token = Some("token".to_string());
        args.plan_endpoint = Some("http://127.0.0.1:1/plan".to_string());
        // No --target-file, no --binary, no --release.
        let err = publish(&store, &OpFlags::default(), args).unwrap_err();
        assert!(
            matches!(&err, OpError::InvalidArgument(m) if m.contains("--release")),
            "expected error mentioning --release, got: {err:?}"
        );
    }

    #[test]
    fn parse_owner_repo_splits_correctly() {
        let (owner, repo) = parse_owner_repo("greenticai/greentic-start");
        assert_eq!(owner, "greenticai");
        assert_eq!(repo, "greentic-start");

        let (owner2, repo2) = parse_owner_repo("greentic-start");
        assert_eq!(owner2, "greenticai");
        assert_eq!(repo2, "greentic-start");
    }
}
