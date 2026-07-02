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

use std::path::PathBuf;

use greentic_deploy_spec::{EnvId, Environment};
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
/// Store-canonical secret names (single underscore — the runtime reader
/// collapses `__` to `_`, so a double-underscore name would never be found).
const CERT_NAME: &str = "updater_cert";
const KEY_NAME: &str = "updater_key";
const CA_NAME: &str = "updater_ca";
const CA_URL_NAME: &str = "updater_ca_url";

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
fn control_url_is_acceptable(raw: &str) -> bool {
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
/// `{name, store_uri}` written, for the outcome. Partial failure is recoverable
/// by re-running `enroll` (each write overwrites).
fn persist_enrollment(
    store: &LocalFsStore,
    env: &Environment,
    env_id: &EnvId,
    kind_path: &str,
    tenant: &str,
    ca_url: &str,
    enrollment: &greentic_update::enroll::Enrollment,
) -> Result<Vec<Value>, OpError> {
    // The certificate is written LAST as a commit marker: `status` (and the
    // Phase 2 consumer) key on `updater_cert`, so a failure part-way through
    // leaves the env reporting not-enrolled rather than half-enrolled. Re-running
    // `enroll` overwrites the whole set. The dev-store/Vault backends have no
    // cross-key transaction, so this ordering is the atomicity we can offer.
    let items = [
        (KEY_NAME, enrollment.client_key_pem.as_str()),
        (CA_NAME, enrollment.ca_pem.as_str()),
        (CA_URL_NAME, ca_url),
        (CERT_NAME, enrollment.client_cert_pem.as_str()),
    ];
    let mut stored = Vec::with_capacity(items.len());
    for (name, value) in items {
        let rel_path = tls_rel_path(tenant, name);
        let (store_uri, _extra) = put_env_secret(store, env, env_id, kind_path, &rel_path, value)?;
        stored.push(json!({"name": name, "store_uri": store_uri}));
    }
    Ok(stored)
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

    let cert_rel = tls_rel_path(&tenant, CERT_NAME);
    let (cert_pem, _store_uri, _extra) =
        get_env_secret(store, &env, &env_id, kind_path, &cert_rel)?;

    let body = match cert_pem {
        None => json!({
            "environment_id": env_id.as_str(),
            "tenant": tenant,
            "secrets_kind": secrets.kind.to_string(),
            "enrolled": false,
        }),
        Some(pem) => {
            let info = greentic_update::tls::parse_cert_info(&pem).map_err(|e| {
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
/// `env_apply` verifies the applied bytes against the signed plan), and manifest
/// content that writes non-rollbackable dev-store secrets (`secrets[]` and
/// `messaging_endpoints[]`) is refused (the snapshot does not cover the
/// dev-store). Concurrent apply on one env is single-flight: `begin_apply_checked`
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

    // Stage gate. Only a `staged` plan is applicable. A plan stuck in
    // `applying` is the residue of a prior crash between the transitions — fail
    // it closed (the operator re-stages via `op updates get`, which resumes an
    // identical plan). Any other stage (still downloading, or already terminal)
    // is a plain argument error.
    let stage = staged
        .stage()
        .map_err(|e| OpError::Conflict(format!("read update staging stage: {e}")))?;
    match stage {
        UpdateStage::Staged => {}
        UpdateStage::Applying => {
            staged
                .transition(UpdateStage::Failed)
                .map_err(|e| OpError::Conflict(format!("fail stale `applying` plan: {e}")))?;
            return Err(OpError::Conflict(format!(
                "plan `{}` was stuck in `applying` from a prior crash and has been marked \
                 `failed`; re-stage with `op updates get` and re-apply",
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

    // The downgrade + compat re-gate moves INTO the `begin_apply_checked`
    // predicate below, so it runs atomically with the `staged → applying`
    // transition against a lock-held applied-set snapshot (closing the TOCTOU
    // where a newer plan applies between the re-gate and the transition).

    // Re-verify every declared artifact's on-disk checksum, fail closed.
    for artifact in &verified.plan.artifacts {
        if let Err(e) = staged.verify_artifact_on_disk(artifact) {
            let _ = staged.transition(UpdateStage::Rejected);
            return Err(OpError::Conflict(format!(
                "staged artifact `{}` failed integrity re-check: {e}",
                artifact.name
            )));
        }
    }

    // The plan's signed target manifest drives the apply.
    let target = verified.plan.target.clone();
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
                // The target left `staged` between the pre-check and the lock (a
                // concurrent transition), or a plan marker is corrupt — fail
                // closed without mutating.
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
                staged.transition(UpdateStage::Applied).map_err(|e| {
                    OpError::Conflict(format!("mark plan applied (applying → applied): {e}"))
                })?;
                // Best-effort retention of terminal plans (never evicts active).
                let _ = root.apply_retention(&RetentionPolicy { keep_terminal: 5 });
                let outcome = OpOutcome::new(
                    NOUN,
                    "apply",
                    json!({
                        "environment_id": env_id.as_str(),
                        "plan_id": verified.plan.plan_id,
                        "sequence": verified.plan.sequence,
                        "plan_sha256": verified.plan_sha256,
                        "snapshot_id": snap_id.to_string(),
                        "stage": UpdateStage::Applied.as_str(),
                        "apply_result": apply_outcome.result,
                    }),
                );
                Ok((outcome, super::AuditGens::NONE))
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
    // Fail closed on manifest content this increment cannot apply *safely*.
    check_applyable_manifest(&manifest)?;
    Ok(verified)
}

/// Reject a target manifest whose apply/rollback this increment cannot yet
/// guarantee. These are fail-closed scope guards, not permanent limits:
///
/// - **dev-store secret side effects** — `env_apply` writes dev-store secret
///   material for `secrets[]` (a `put-secret` step) and for
///   `messaging_endpoints[]` (a telegram-class endpoint auto-provisions a
///   webhook secret). The P0b snapshot does not capture the dev-store, so a
///   post-apply rollback could not undo those writes. Both are refused until
///   snapshot coverage is extended. (Audited against `env_apply`'s `StepOp`
///   execute arms: only `PutSecret` and `EndpointAdd` write dev-store secrets.)
/// - **unpinned bundles** — apply-updates does not yet source bundle artifacts
///   from the verified staged set, so require a `bundle_digest` on every bundle
///   (and revision); `env_apply` then pins the applied bytes to the DSSE-signed
///   manifest, so unpinned / trust-on-first-use content can't be applied.
///   (Materializing from the staged blobs → follow-up.)
fn check_applyable_manifest(manifest: &EnvManifest) -> Result<(), OpError> {
    // Anything that writes dev-store secrets is non-rollbackable under the P0b
    // snapshot, so fail closed on it.
    if !manifest.secrets.is_empty() {
        return Err(dev_store_secret_err("secrets[]"));
    }
    if !manifest.messaging_endpoints.is_empty() {
        return Err(dev_store_secret_err("messaging_endpoints[]"));
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

fn dev_store_secret_err(field: &str) -> OpError {
    OpError::InvalidArgument(format!(
        "update plan target declares {field}; applying it via an update plan is not yet supported \
         — env_apply writes dev-store secret material that the environment snapshot does not \
         cover, so a rollback could not undo it"
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
            // Bound the download by the resolver's declared size *before* fetching
            // the body (best-effort — `size_bytes` may be 0 if unknown).
            reject_oversize(artifact, descriptor.size_bytes)?;
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

    let read_enrolled = |name: &str| -> Result<String, OpError> {
        let rel = tls_rel_path(&tenant, name);
        let (value, _uri, _extra) = get_env_secret(store, env, env_id, kind_path, &rel)?;
        value.ok_or_else(|| {
            OpError::NotFound(format!(
                "env `{env_id}` is not enrolled for updates (missing `{name}`); \
                 run `op updates enroll` first"
            ))
        })
    };
    let cert_pem = read_enrolled(CERT_NAME)?;
    let key_pem = read_enrolled(KEY_NAME)?;
    let ca_pem = read_enrolled(CA_NAME)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::secrets::{DEV_STORE_KIND_PATH, get_env_secret, put_env_secret};
    use crate::cli::tests_common::{make_binding, make_env};
    use greentic_deploy_spec::CapabilitySlot;
    use tempfile::tempdir;

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
        // Seed the cert exactly where `enroll` would persist it.
        put_env_secret(
            &store,
            &env,
            &env_id,
            DEV_STORE_KIND_PATH,
            "acme/_/tls/updater_cert",
            TEST_CERT_PEM,
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
    fn persist_enrollment_writes_all_four_secrets_then_status_reads_them() {
        // Exercises the durable side-effect of `enroll` without a CA: build a
        // synthetic Enrollment, persist it, read all four secrets back through
        // the same dispatch a reader uses, and confirm `status` finds the cert.
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

        // All four artifacts written; the certificate is written LAST (commit marker).
        let names: Vec<&str> = stored.iter().map(|e| e["name"].as_str().unwrap()).collect();
        assert_eq!(names, vec![KEY_NAME, CA_NAME, CA_URL_NAME, CERT_NAME]);
        assert_eq!(
            stored[3]["store_uri"].as_str().unwrap(),
            "secrets://local/acme/_/tls/updater_cert"
        );

        // Read each back through get_env_secret (the reader's dispatch).
        let read = |name: &str| {
            get_env_secret(
                &store,
                &env,
                &env_id,
                DEV_STORE_KIND_PATH,
                &tls_rel_path("acme", name),
            )
            .unwrap()
            .0
        };
        assert_eq!(
            read(KEY_NAME).as_deref(),
            Some(enrollment.client_key_pem.as_str())
        );
        assert_eq!(read(CERT_NAME).as_deref(), Some(TEST_CERT_PEM));
        assert_eq!(read(CA_NAME).as_deref(), Some(enrollment.ca_pem.as_str()));
        assert_eq!(read(CA_URL_NAME).as_deref(), Some(ca_url));

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
        let env = make_env("local");
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
    fn apply_fails_closed_on_stale_applying_plan() {
        use greentic_update::staging::UpdateStage;
        let dir = tempdir().unwrap();
        let updates_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (priv7, tk7) = key_pair(7);
        env_trusting(&store, &tk7);
        stage_local(updates_dir.path(), "plan-1", 1, &priv7, &tk7);
        // Simulate a crash mid-apply: the plan is left in Applying.
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
        assert!(matches!(err, OpError::Conflict(m) if m.contains("prior crash")));
        // The stale plan was failed closed.
        assert_eq!(
            on_disk_stage(updates_dir.path(), "plan-1"),
            UpdateStage::Failed
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
    fn apply_rejects_target_declaring_secrets() {
        use greentic_update::staging::{UpdateStage, UpdatesRoot};
        let dir = tempdir().unwrap();
        let updates_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (priv7, tk7) = key_pair(7);
        env_trusting(&store, &tk7);

        // A signed target that declares secrets[] — refused fail-closed because
        // the snapshot cannot roll a secret rotation back.
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
        assert!(matches!(err, OpError::InvalidArgument(m) if m.contains("secrets")));
        // Refused pre-mutation ⇒ marked Rejected, env untouched.
        assert_eq!(
            on_disk_stage(updates_dir.path(), "plan-sec"),
            UpdateStage::Rejected
        );
    }

    #[test]
    fn apply_rejects_target_declaring_messaging_endpoints() {
        use greentic_update::staging::{UpdateStage, UpdatesRoot};
        let dir = tempdir().unwrap();
        let updates_dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let (priv7, tk7) = key_pair(7);
        env_trusting(&store, &tk7);

        // Telegram-class endpoints auto-provision a webhook secret in the
        // dev-store, which the snapshot does not cover ⇒ refused fail-closed.
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
        assert!(matches!(err, OpError::InvalidArgument(m) if m.contains("messaging_endpoints")));
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
}
