//! End-to-end proof of the PR-4.2a+ remote slices (env lifecycle,
//! revisions, traffic, pack/extension bindings, trust root, bundles): the REAL
//! `HttpEnvironmentStore` client (blocking reqwest, A8 envelope + audit
//! validation) drives the REAL operator-store-server (axum + SQLite) over
//! a loopback listener — no mocks on either side.
//!
//! This is the wire-compatibility gate for the shared
//! `greentic_deploy_spec::engine` payload types: the client serializes
//! them, the server deserializes the same structs, and both apply the same
//! engine transforms. A drift in either direction fails here before it can
//! ship.

use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use greentic_deploy_spec::{
    BundleDeployment, BundleDeploymentStatus, BundleId, CapabilitySlot, CustomerId, DeploymentId,
    EnvId, EnvPackBinding, EnvironmentHostConfig, ExtensionBinding, ExtensionKey, IdempotencyKey,
    PackDescriptor, PackId, PackListEntry, PartyId, Precondition, RevenueShareEntry, RevisionId,
    RevisionLifecycle, RouteBinding, SchemaVersion, SemVer, TenantSelector, TrafficSplitEntry,
};
use greentic_deployer::environment::{
    AddBundlePayload, AddMessagingEndpointPayload, FieldUpdate, MigrateMergePayload,
    SetMessagingWelcomeFlowPayload, SetTrafficSplitPayload, StageRevisionPayload,
    UpdateBundlePayload, UpdateEnvironmentPayload, WarmRevisionPayload,
};
use greentic_deployer::environment::{
    AuthMethod, EnvironmentMutations, HealthCheckId, HealthGateFailure, HttpEnvironmentStore,
    LifecycleError, StoreError,
};
use greentic_operator_store_server::http::router_with_operator_key;
use greentic_operator_store_server::sqlite::SqliteEnvironmentStore;
use greentic_operator_store_server::storage::EnvironmentStorage;
use greentic_operator_trust::test_support::keypair;
use url::Url;

fn env_id(raw: &str) -> EnvId {
    EnvId::try_from(raw).expect("valid env id")
}

fn idem(raw: &str) -> IdempotencyKey {
    IdempotencyKey::new(raw).expect("valid idempotency key")
}

fn stage_payload(deployment_id: DeploymentId) -> StageRevisionPayload {
    StageRevisionPayload {
        revision_id: RevisionId::new(),
        deployment_id,
        bundle_digest: "sha256:00".to_string(),
        pack_list: vec![PackListEntry {
            pack_id: greentic_deploy_spec::PackId::new("greentic.test.pack"),
            version: SemVer::new(1, 0, 0),
            digest: "sha256:00".to_string(),
            source_uri: None,
        }],
        pack_list_lock_ref: PathBuf::from("pack-list.lock"),
        pack_config_refs: Vec::new(),
        config_digest: "sha256:00".to_string(),
        signature_sidecar_ref: PathBuf::from("rev.sig"),
        drain_seconds: 30,
    }
}

/// Seed a bundle deployment into an existing env directly through the
/// server's storage backend — the bundles verb group has no server route
/// yet (PR-4.2e+).
async fn seed_deployment(backend: &SqliteEnvironmentStore, id: &EnvId) -> DeploymentId {
    let loaded = backend.load_env(id).await.expect("load env");
    let mut env = loaded.value;
    let deployment_id = DeploymentId::new();
    env.bundles.push(BundleDeployment {
        schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
        deployment_id,
        env_id: id.clone(),
        bundle_id: BundleId::new("fast2flow"),
        customer_id: CustomerId::new("local-dev"),
        status: BundleDeploymentStatus::Active,
        current_revisions: Vec::new(),
        route_binding: RouteBinding {
            hosts: Vec::new(),
            path_prefixes: Vec::new(),
            tenant_selector: TenantSelector {
                tenant: "default".to_string(),
                team: "default".to_string(),
            },
        },
        revenue_share: vec![RevenueShareEntry {
            party_id: PartyId::new("greentic"),
            basis_points: 10_000,
        }],
        revenue_policy_ref: PathBuf::from("revenue.json"),
        usage: None,
        created_at: Utc::now(),
        authorization_ref: PathBuf::from("auth.json"),
        config_overrides: Default::default(),
    });
    let precondition = Precondition::matching(loaded.revision.etag, loaded.revision.generation);
    backend
        .update_env(&env, &precondition)
        .await
        .expect("seed deployment");
    deployment_id
}

fn host_config(raw: &str) -> EnvironmentHostConfig {
    EnvironmentHostConfig {
        env_id: env_id(raw),
        region: Some("eu-west-1".to_string()),
        tenant_org_id: None,
        listen_addr: None,
        public_base_url: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_env_lifecycle_end_to_end() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = SqliteEnvironmentStore::open(&dir.path().join("store.sqlite"))
        .await
        .expect("open sqlite store");
    let backend = Arc::new(store);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let serve_backend = Arc::clone(&backend);
    // The server operator key lives in the test's TempDir — the trust-root
    // bootstrap verb mints it there instead of `~/.greentic`.
    let operator_key_path = dir.path().join("operator-key.pem");
    tokio::spawn(async move {
        axum::serve(
            listener,
            router_with_operator_key(serve_backend, operator_key_path),
        )
        .await
        .expect("serve");
    });

    // The blocking reqwest client must not run on a tokio worker thread.
    tokio::task::spawn_blocking(move || {
        let base = Url::parse(&format!("http://{addr}/")).expect("base url");
        let store = HttpEnvironmentStore::new(base, AuthMethod::None).expect("client");
        let id = env_id("local");

        // Create — server runs engine::fresh_environment, client validates
        // the A8 envelope (audit binds env + idempotency key).
        let created = store
            .create_environment(&id, "local".to_string(), host_config("local"))
            .expect("create environment");
        assert_eq!(created.environment_id, id);
        assert_eq!(created.host_config.region.as_deref(), Some("eu-west-1"));

        // Duplicate create — server's 409 `already-exists` body maps onto
        // the same `Conflict` noun the local store uses.
        let err = store
            .create_environment(&id, "local".to_string(), host_config("local"))
            .expect_err("duplicate create must conflict");
        assert!(
            matches!(&err, StoreError::Conflict(msg) if msg.contains("already exists")),
            "unexpected error: {err:?}"
        );

        // Update — tri-state patch travels as the shared wire encoding
        // (Set → {"value"}, Clear → {"clear": true}, Keep → absent).
        let updated = store
            .update_environment(
                &id,
                UpdateEnvironmentPayload {
                    name: Some("renamed".to_string()),
                    region: FieldUpdate::Clear,
                    tenant_org_id: FieldUpdate::Set("org-1".to_string()),
                    listen_addr: FieldUpdate::Keep,
                    public_base_url: FieldUpdate::Keep,
                },
            )
            .expect("update environment");
        assert_eq!(updated.name, "renamed");
        assert_eq!(updated.host_config.region, None, "Clear must persist None");
        assert_eq!(updated.host_config.tenant_org_id.as_deref(), Some("org-1"));

        // Migrate-bindings without a seed against a missing env → NotFound.
        let err = store
            .migrate_merge_bindings(
                &env_id("ghost"),
                MigrateMergePayload {
                    packs: Vec::new(),
                    extensions: Vec::new(),
                    seed_if_missing: None,
                },
            )
            .expect_err("missing target without seed must be NotFound");
        assert!(
            matches!(err, StoreError::NotFound(_)),
            "unexpected error: {err:?}"
        );

        // Merge into the existing env (empty merge set — referential
        // fixtures for pack bindings live in the server-side route tests;
        // here the point is the verb's wire round-trip).
        let (slots, extensions) = store
            .migrate_merge_bindings(
                &id,
                MigrateMergePayload {
                    packs: Vec::new(),
                    extensions: Vec::new(),
                    seed_if_missing: None,
                },
            )
            .expect("merge into existing env");
        assert!(slots.is_empty() && extensions.is_empty());
    })
    .await
    .expect("client task");

    // ----- PR-4.2b: the revision verb group over the same wire. -----

    let id = env_id("local");
    let deployment_id = seed_deployment(&backend, &id).await;

    let client_id = id.clone();
    tokio::task::spawn_blocking(move || {
        let base = Url::parse(&format!("http://{addr}/")).expect("base url");
        let store = HttpEnvironmentStore::new(base, AuthMethod::None).expect("client");
        let id = client_id;

        // Stage — server resolves the deployment, assigns sequence 1.
        let staged = store
            .stage_revision(&id, stage_payload(deployment_id), idem("k-stage-1"))
            .expect("stage revision");
        assert_eq!(staged.lifecycle, RevisionLifecycle::Staged);
        assert_eq!(staged.sequence, 1);

        // Warm with a FAILING gate — the server persists the `Failed` flip
        // and the client reconstructs the SAME typed error the local store
        // raises (`StoreError::Lifecycle(HealthGateFailed)`), so the CLI's
        // committed-on-error handling behaves identically remotely.
        let err = store
            .warm_revision(
                &id,
                WarmRevisionPayload {
                    revision_id: staged.revision_id,
                    health_gate: Err(HealthGateFailure {
                        failed_checks: vec![HealthCheckId::RouteTable],
                        message: "route table invalid".to_string(),
                    }),
                    expected_lifecycle: RevisionLifecycle::Staged,
                },
                idem("k-warm-fail"),
            )
            .expect_err("failing gate must surface");
        assert!(
            matches!(
                &err,
                StoreError::Lifecycle(inner) if matches!(
                    inner.as_ref(),
                    LifecycleError::HealthGateFailed { failed_checks, .. }
                        if failed_checks == &vec![HealthCheckId::RouteTable]
                )
            ),
            "unexpected error: {err:?}"
        );

        // Stage a second revision and walk it Staged → Ready → Draining →
        // Archived through the remote verbs.
        let rev = store
            .stage_revision(&id, stage_payload(deployment_id), idem("k-stage-2"))
            .expect("stage second revision");
        assert_eq!(rev.sequence, 2);

        let warmed = store
            .warm_revision(
                &id,
                WarmRevisionPayload {
                    revision_id: rev.revision_id,
                    health_gate: Ok(()),
                    expected_lifecycle: RevisionLifecycle::Staged,
                },
                idem("k-warm-ok"),
            )
            .expect("warm revision");
        assert_eq!(warmed.revision.lifecycle, RevisionLifecycle::Ready);
        assert!(warmed.revision.warmed_at.is_some());
        assert_eq!(warmed.starting_lifecycle, RevisionLifecycle::Staged);

        let drained = store
            .drain_revision(&id, rev.revision_id, idem("k-drain"))
            .expect("drain revision");
        assert_eq!(drained.revision.lifecycle, RevisionLifecycle::Draining);

        let archived = store
            .archive_revision(&id, rev.revision_id, idem("k-archive"))
            .expect("archive revision");
        assert_eq!(archived.revision.lifecycle, RevisionLifecycle::Archived);
        assert_eq!(archived.starting_lifecycle, RevisionLifecycle::Draining);

        // Unknown revision → the server's 404 `dependent-not-found` maps to
        // the same noun the local store uses.
        let err = store
            .drain_revision(&id, RevisionId::new(), idem("k-drain-ghost"))
            .expect_err("unknown revision must be dependent-not-found");
        assert!(
            matches!(err, StoreError::DependentNotFound(_)),
            "unexpected error: {err:?}"
        );

        // ----- PR-4.2c: the traffic verb group over the same wire. -----

        // A fresh `Ready` revision to route traffic at (the previous one
        // was archived above).
        let staged_third = store
            .stage_revision(&id, stage_payload(deployment_id), idem("k-stage-3"))
            .expect("stage third revision");
        let r3 = store
            .warm_revision(
                &id,
                WarmRevisionPayload {
                    revision_id: staged_third.revision_id,
                    health_gate: Ok(()),
                    expected_lifecycle: RevisionLifecycle::Staged,
                },
                idem("k-warm-3"),
            )
            .expect("warm third revision")
            .revision
            .revision_id;
        let full_weight = || SetTrafficSplitPayload {
            deployment_id,
            entries: vec![TrafficSplitEntry {
                revision_id: r3,
                weight_bps: 10_000,
            }],
            updated_by: "e2e".to_string(),
            authorization_ref: None,
        };

        // Set — the server resolves the deployment, runs §5.3 admission,
        // and persists generation 0. The outcome carries the env snapshot
        // the CLI's telemetry emission reads.
        let outcome = store
            .set_traffic_split(&id, full_weight(), idem("k-traffic-1"))
            .expect("set traffic split");
        assert_eq!(outcome.new_generation, Some(0));
        assert_eq!(outcome.split.idempotency_key, "k-traffic-1");
        assert_eq!(outcome.environment.environment_id, id);

        // Same-key-same-request retry → the PR-4.3 transport replay: the
        // server returns the ORIGINAL ledgered response verbatim (so
        // `new_generation` echoes the first commit, unlike the LocalFS
        // domain no-op's `None`), the client's audit/key binding checks
        // pass against the original audit event, and nothing re-applies.
        let replay = store
            .set_traffic_split(&id, full_weight(), idem("k-traffic-1"))
            .expect("replay is a verbatim success");
        assert_eq!(replay.new_generation, Some(0));
        assert_eq!(replay.split.idempotency_key, "k-traffic-1");

        // Reusing a consumed key for a DIFFERENT request is the typed A8
        // idempotency conflict, raised at the replay gate.
        let err = store
            .rollback_traffic_split(&id, deployment_id, idem("k-traffic-1"))
            .expect_err("key reuse across requests");
        assert!(
            matches!(&err, StoreError::Conflict(msg) if msg.contains("idempotency")),
            "unexpected error: {err:?}"
        );

        // Rollback without a prior snapshot → the same `Conflict` noun the
        // local store raises.
        let err = store
            .rollback_traffic_split(&id, deployment_id, idem("k-traffic-rb"))
            .expect_err("no prior version to roll back to");
        assert!(
            matches!(err, StoreError::Conflict(_)),
            "unexpected error: {err:?}"
        );

        // ----- PR-4.2d: the binding verb groups over the same wire. -----

        let pack_binding = |kind: &str| EnvPackBinding {
            slot: CapabilitySlot::Secrets,
            kind: PackDescriptor::try_new(format!("{kind}@1.0.0")).expect("descriptor"),
            pack_ref: PackId::new(kind),
            answers_ref: None,
            generation: 0,
            previous_binding_ref: None,
        };
        let added = store
            .add_pack_binding(&id, pack_binding("greentic.secrets"), idem("k-pack-add"))
            .expect("add pack binding");
        assert_eq!(added.slot, CapabilitySlot::Secrets);

        // Duplicate add → the same `Conflict` noun the local store raises.
        let err = store
            .add_pack_binding(&id, pack_binding("greentic.other"), idem("k-pack-add-2"))
            .expect_err("slot already bound");
        assert!(
            matches!(err, StoreError::Conflict(_)),
            "unexpected error: {err:?}"
        );

        let (updated, generation) = store
            .update_pack_binding(
                &id,
                CapabilitySlot::Secrets,
                pack_binding("greentic.vault"),
                idem("k-pack-update"),
            )
            .expect("update pack binding");
        assert_eq!(generation, 1);
        assert!(
            updated.previous_binding_ref.is_some(),
            "prior binding stashed for one-step rollback"
        );

        let (restored, generation) = store
            .rollback_pack_binding(&id, CapabilitySlot::Secrets, idem("k-pack-rollback"))
            .expect("rollback pack binding");
        assert_eq!(generation, 2);
        assert_eq!(restored.kind.as_str(), "greentic.secrets@1.0.0");
        assert!(restored.previous_binding_ref.is_none());

        let ext_binding = |pack_ref: &str| ExtensionBinding {
            kind: PackDescriptor::try_new("greentic.memory@0.1.0").expect("descriptor"),
            pack_ref: PackId::new(pack_ref),
            instance_id: Some("alt".to_string()),
            answers_ref: None,
            generation: 0,
            previous_binding_ref: None,
        };
        let ext_key = ExtensionKey::new("greentic.memory", Some("alt".to_string()));
        store
            .add_extension_binding(&id, ext_binding("greentic.memory"), idem("k-ext-add"))
            .expect("add extension binding");
        let (updated, generation) = store
            .update_extension_binding(
                &id,
                ext_key.clone(),
                ext_binding("greentic.memory-v2"),
                idem("k-ext-update"),
            )
            .expect("update extension binding");
        assert_eq!(generation, 1);
        assert_eq!(updated.pack_ref.as_str(), "greentic.memory-v2");

        let (removed, _) = store
            .remove_extension_binding(&id, ext_key.clone(), idem("k-ext-remove"))
            .expect("remove extension binding");
        assert_eq!(removed.pack_ref.as_str(), "greentic.memory-v2");

        // Removed key → the server's 404 `dependent-not-found` maps to the
        // same noun the local store uses.
        let err = store
            .remove_extension_binding(&id, ext_key, idem("k-ext-remove-2"))
            .expect_err("key no longer bound");
        assert!(
            matches!(err, StoreError::DependentNotFound(_)),
            "unexpected error: {err:?}"
        );

        // ----- PR-4.2f: the trust-root verb group over the same wire. -----

        // Bootstrap mints the SERVER's operator key (no request body — the
        // PR-3b wire contract) and grants it on the env trust root.
        let seed = store.bootstrap_trust_root(&id).expect("bootstrap");
        assert_eq!(seed.trusted_key_count, 1);
        assert!(seed.public_key_pem.contains("PUBLIC KEY"));

        // Already bootstrapped — seed-if-absent's no-op travels as a
        // `null` result and decodes back to `None`.
        let again = store
            .seed_trust_root_if_absent(&id)
            .expect("seed after bootstrap");
        assert!(again.is_none(), "seed must no-op once bootstrapped");

        // Add a caller-supplied key; the shared validation canonicalizes
        // and the outcome echoes the supplied id (local parity).
        let (pem, key_id) = keypair(81);
        let added = store
            .add_trusted_key(&id, key_id.clone(), pem.clone(), idem("k-trust-add"))
            .expect("add trusted key");
        assert_eq!(added.added_key_id, key_id);
        assert_eq!(added.trusted_key_count, 2);

        // Mismatched id → the server's 400 `invalid-request` maps onto the
        // same `InvalidArgument` noun the CLI mapper uses.
        let (_pem_b, id_b) = keypair(82);
        let err = store
            .add_trusted_key(&id, id_b, pem.clone(), idem("k-trust-add-bad"))
            .expect_err("mismatched key id must be rejected");
        assert!(
            matches!(err, StoreError::InvalidArgument(_)),
            "unexpected error: {err:?}"
        );

        // Remove returns the recovery PEM; the repeat is a silent no-op.
        let removed = store
            .remove_trusted_key(&id, key_id.clone(), idem("k-trust-rm"))
            .expect("remove trusted key");
        assert_eq!(
            removed.removed_public_key_pem.as_deref(),
            Some(pem.as_str())
        );
        assert_eq!(removed.trusted_key_count, 1);
        let noop = store
            .remove_trusted_key(&id, key_id, idem("k-trust-rm-2"))
            .expect("no-op remove");
        assert!(noop.removed_public_key_pem.is_none());
        assert_eq!(noop.trusted_key_count, 1);

        // ----- PR-4.2g: the bundles verb group over the same wire. -----
        // The trust root still holds the server's bootstrapped operator
        // key (the remove above only revoked the caller-supplied one), so
        // the server can sign revenue-policy versions.

        let added_bundle = store
            .add_bundle(
                &id,
                AddBundlePayload {
                    bundle_id: BundleId::new("e2e-bundle"),
                    customer_id: CustomerId::new("cust-e2e"),
                    revenue_share: vec![RevenueShareEntry {
                        party_id: PartyId::new("greentic"),
                        basis_points: 10_000,
                    }],
                    route_binding: None,
                    authorization_ref: None,
                    config_overrides: Default::default(),
                },
                idem("k-bundle-add"),
            )
            .expect("add bundle");
        assert_eq!(added_bundle.bundle_id.as_str(), "e2e-bundle");
        assert_eq!(
            added_bundle.revenue_policy_ref,
            PathBuf::from("billing-policies/e2e-bundle/cust-e2e/v1.json.sig"),
            "server-minted v1 policy ref"
        );

        // Duplicate (bundle, customer) → the server's 409 `already-exists`
        // folds onto the same `Conflict` noun the local store raises.
        let err = store
            .add_bundle(
                &id,
                AddBundlePayload {
                    bundle_id: BundleId::new("e2e-bundle"),
                    customer_id: CustomerId::new("cust-e2e"),
                    revenue_share: vec![RevenueShareEntry {
                        party_id: PartyId::new("greentic"),
                        basis_points: 10_000,
                    }],
                    route_binding: None,
                    authorization_ref: None,
                    config_overrides: Default::default(),
                },
                idem("k-bundle-add-dup"),
            )
            .expect_err("duplicate (bundle, customer) must conflict");
        assert!(
            matches!(err, StoreError::Conflict(_)),
            "unexpected error: {err:?}"
        );

        // A revenue-share patch chains the next signed policy version.
        let updated_bundle = store
            .update_bundle(
                &id,
                UpdateBundlePayload {
                    deployment_id: added_bundle.deployment_id,
                    status: Some(BundleDeploymentStatus::Paused),
                    route_binding: None,
                    revenue_share: Some(vec![RevenueShareEntry {
                        party_id: PartyId::new("partner"),
                        basis_points: 10_000,
                    }]),
                    config_overrides: None,
                },
                idem("k-bundle-update"),
            )
            .expect("update bundle");
        assert_eq!(updated_bundle.status, BundleDeploymentStatus::Paused);
        assert_eq!(
            updated_bundle.revenue_policy_ref,
            PathBuf::from("billing-policies/e2e-bundle/cust-e2e/v2.json.sig"),
            "revenue patch advances the policy chain"
        );

        // Quiesced (no revisions, no splits) → remove compacts cleanly.
        let removed_bundle = store
            .remove_bundle(&id, added_bundle.deployment_id, idem("k-bundle-rm"))
            .expect("remove bundle");
        assert_eq!(
            removed_bundle.deployment.deployment_id,
            added_bundle.deployment_id
        );
        assert!(removed_bundle.pruned_revision_ids.is_empty());

        // ----- PR-4.2h: the messaging verb group over the same wire. -----

        // A deployed bundle for the link/welcome verbs to reference.
        let msg_bundle = store
            .add_bundle(
                &id,
                AddBundlePayload {
                    bundle_id: BundleId::new("e2e-msg-bundle"),
                    customer_id: CustomerId::new("cust-e2e"),
                    revenue_share: vec![RevenueShareEntry {
                        party_id: PartyId::new("greentic"),
                        basis_points: 10_000,
                    }],
                    route_binding: None,
                    authorization_ref: None,
                    config_overrides: Default::default(),
                },
                idem("k-msg-bundle"),
            )
            .expect("add bundle for messaging");

        // Add: the server mints the endpoint id and stamps the idem key.
        let ep = store
            .add_messaging_endpoint(
                &id,
                AddMessagingEndpointPayload {
                    provider_id: "legal-bot".to_string(),
                    provider_type: "teams".to_string(),
                    display_name: "Legal".to_string(),
                    secret_refs: Vec::new(),
                    updated_by: "e2e".to_string(),
                },
                idem("k-msg-add"),
            )
            .expect("add messaging endpoint");
        assert_eq!(ep.provider_id, "legal-bot");
        assert_eq!(ep.updated_by, "e2e#idem=add:k-msg-add");

        // Telegram-class add → the server's 501 maps onto the same
        // `NotYetImplemented` noun PR-4.0 reserved for it.
        let err = store
            .add_messaging_endpoint(
                &id,
                AddMessagingEndpointPayload {
                    provider_id: "tg-bot".to_string(),
                    provider_type: "telegram".to_string(),
                    display_name: "Telegram".to_string(),
                    secret_refs: Vec::new(),
                    updated_by: "e2e".to_string(),
                },
                idem("k-msg-add-tg"),
            )
            .expect_err("telegram-class add needs the Phase D secrets sink");
        assert!(
            matches!(err, StoreError::NotYetImplemented(_)),
            "unexpected error: {err:?}"
        );

        // Link → welcome-flow → unlink-blocked-by-welcome → remove.
        let linked = store
            .link_messaging_bundle(
                &id,
                ep.endpoint_id,
                msg_bundle.bundle_id.clone(),
                "e2e".to_string(),
                idem("k-msg-link"),
            )
            .expect("link bundle");
        assert_eq!(linked.linked_bundles, vec![msg_bundle.bundle_id.clone()]);
        assert_eq!(linked.generation, 1);

        let with_welcome = store
            .set_messaging_welcome_flow(
                &id,
                SetMessagingWelcomeFlowPayload {
                    endpoint_id: ep.endpoint_id,
                    bundle_id: msg_bundle.bundle_id.clone(),
                    pack_id: PackId::new("welcome-pack"),
                    flow_id: "hello".to_string(),
                    updated_by: "e2e".to_string(),
                },
                idem("k-msg-welcome"),
            )
            .expect("set welcome flow");
        assert_eq!(
            with_welcome
                .welcome_flow
                .as_ref()
                .map(|w| w.flow_id.as_str()),
            Some("hello")
        );

        // The welcome-owner guard folds onto the local `Conflict` noun.
        let err = store
            .unlink_messaging_bundle(
                &id,
                ep.endpoint_id,
                msg_bundle.bundle_id.clone(),
                "e2e".to_string(),
                idem("k-msg-unlink"),
            )
            .expect_err("welcome owner must block unlink");
        assert!(
            matches!(err, StoreError::Conflict(_)),
            "unexpected error: {err:?}"
        );

        // Rotate → the server's 501 (no secrets sink yet).
        let err = store
            .rotate_messaging_webhook_secret(
                &id,
                ep.endpoint_id,
                "e2e".to_string(),
                idem("k-msg-rotate"),
            )
            .expect_err("rotate needs the Phase D secrets sink");
        assert!(
            matches!(err, StoreError::NotYetImplemented(_)),
            "unexpected error: {err:?}"
        );

        // Remove is idempotent: second call succeeds on the absent id.
        let removed_eid = store
            .remove_messaging_endpoint(&id, ep.endpoint_id)
            .expect("remove endpoint");
        assert_eq!(removed_eid, ep.endpoint_id);
        store
            .remove_messaging_endpoint(&id, ep.endpoint_id)
            .expect("idempotent re-remove");

        staged.revision_id
    })
    .await
    .map(|failed_rev| async move {
        // The gate failure's `Failed` flip is durable on the server.
        let loaded = backend.load_env(&id).await.expect("load env");
        let failed = loaded
            .value
            .revisions
            .iter()
            .find(|r| r.revision_id == failed_rev)
            .expect("failed revision persisted");
        assert_eq!(failed.lifecycle, RevisionLifecycle::Failed);
    })
    .expect("revision client task")
    .await;
}

/// PR-4.4 backup/restore (A8 #5) over the real wire: the client's inherent
/// backup methods drive the server's bounded backup store; restore is a
/// guarded mutation whose body-carried precondition pins prior state.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_restore_end_to_end() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = SqliteEnvironmentStore::open(&dir.path().join("store.sqlite"))
        .await
        .expect("open sqlite store");
    let backend = Arc::new(store);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let serve_backend = Arc::clone(&backend);
    let operator_key_path = dir.path().join("operator-key.pem");
    tokio::spawn(async move {
        axum::serve(
            listener,
            router_with_operator_key(serve_backend, operator_key_path),
        )
        .await
        .expect("serve");
    });

    let id = env_id("local");

    // Create + snapshot + mutate past the snapshot.
    let client_id = id.clone();
    let backup_manifest = tokio::task::spawn_blocking(move || {
        let base = Url::parse(&format!("http://{addr}/")).expect("base url");
        let store = HttpEnvironmentStore::new(base, AuthMethod::None).expect("client");
        store
            .create_environment(&client_id, "local".to_string(), host_config("local"))
            .expect("create environment");
        let manifest = store
            .create_backup(&client_id, &idem("k-backup-1"))
            .expect("create backup");
        assert_eq!(manifest.env_id, client_id);
        assert_eq!(manifest.generation, 1);
        let listed = store.list_backups(&client_id).expect("list backups");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].backup_id, manifest.backup_id);
        store
            .update_environment(
                &client_id,
                UpdateEnvironmentPayload {
                    name: Some("mutated-past-the-snapshot".to_string()),
                    region: FieldUpdate::Keep,
                    tenant_org_id: FieldUpdate::Keep,
                    listen_addr: FieldUpdate::Keep,
                    public_base_url: FieldUpdate::Keep,
                },
            )
            .expect("update environment");
        manifest
    })
    .await
    .expect("backup client task");

    // The restore precondition pins the CURRENT server state (the client's
    // envelope metadata is not surfaced yet — PR-3b-fu — so read the CAS
    // coordinates through the backend, as an operator would via GET).
    let current = backend.load_env(&id).await.expect("load env");
    assert_eq!(current.value.name, "mutated-past-the-snapshot");
    let pin = Precondition::matching(current.revision.etag, current.revision.generation);

    let client_id = id.clone();
    tokio::task::spawn_blocking(move || {
        let base = Url::parse(&format!("http://{addr}/")).expect("base url");
        let store = HttpEnvironmentStore::new(base, AuthMethod::None).expect("client");

        // A blind restore (empty pin) never deserializes server-side as a
        // pass: the typed 428 maps onto the client's Conflict noun family.
        let err = store
            .restore(
                &client_id,
                &greentic_deploy_spec::RestoreRequest {
                    backup_id: backup_manifest.backup_id.clone(),
                    precondition: Precondition::default(),
                },
                &idem("k-restore-blind"),
            )
            .expect_err("blind restore must be refused");
        assert!(
            matches!(err, StoreError::Conflict(ref msg) if msg.contains("precondition")),
            "unexpected error: {err:?}"
        );

        let outcome = store
            .restore(
                &client_id,
                &greentic_deploy_spec::RestoreRequest {
                    backup_id: backup_manifest.backup_id.clone(),
                    precondition: pin,
                },
                &idem("k-restore-1"),
            )
            .expect("restore");
        assert_eq!(outcome.restored_generation, 3);
        assert_eq!(
            outcome.integrity.digest, backup_manifest.integrity.digest,
            "restored content must hash to the snapshot digest"
        );

        // Delete the backup; restoring from it again is a typed 404.
        store
            .delete_backup(&client_id, &backup_manifest.backup_id, &idem("k-bk-del"))
            .expect("delete backup");
        assert!(
            store
                .list_backups(&client_id)
                .expect("list after delete")
                .is_empty()
        );
    })
    .await
    .expect("restore client task");

    // The restore is durable: content reverted, generation monotonic.
    let restored = backend.load_env(&id).await.expect("load env");
    assert_eq!(restored.value.name, "local");
    assert_eq!(restored.revision.generation, 3);
}

/// PR-4.4 RBAC (A8 #3) over the real wire: the client's `AuthMethod::Bearer`
/// against a token-enforcing server — a valid token deploys, a missing or
/// unknown one maps onto the typed `StoreError::Unauthorized`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rbac_bearer_token_end_to_end() {
    use greentic_operator_store_server::http::{RouterOptions, router_with_options};
    use greentic_operator_store_server::rbac::RbacEngine;
    use sha2::{Digest, Sha256};

    let dir = tempfile::tempdir().expect("temp dir");
    let store = SqliteEnvironmentStore::open(&dir.path().join("store.sqlite"))
        .await
        .expect("open sqlite store");
    let backend = Arc::new(store);

    let token_path = dir.path().join("rbac-tokens.json");
    std::fs::write(
        &token_path,
        serde_json::to_vec(&serde_json::json!({
            "schema": "greentic.store-rbac.v1",
            "tokens": [{
                "token_sha256": hex::encode(Sha256::digest(b"e2e-secret")),
                "actor": "e2e",
                "role": "operator",
            }],
        }))
        .expect("token json"),
    )
    .expect("write token file");
    let rbac = RbacEngine::from_token_file(&token_path).expect("valid token file");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(
            listener,
            router_with_options(
                backend,
                RouterOptions {
                    operator_key_path: Some(dir.path().join("operator-key.pem")),
                    rbac,
                },
            ),
        )
        .await
        .expect("serve");
    });

    tokio::task::spawn_blocking(move || {
        let base = Url::parse(&format!("http://{addr}/")).expect("base url");
        let id = env_id("local");

        // No token → typed Unauthorized (unauthenticated denials are logged
        // but not persisted; only authenticated denials are durably audited;
        // the route tests pin both).
        let anonymous = HttpEnvironmentStore::new(base.clone(), AuthMethod::None).expect("client");
        let err = anonymous
            .create_environment(&id, "local".to_string(), host_config("local"))
            .expect_err("anonymous mutation must be denied");
        assert!(
            matches!(err, StoreError::Unauthorized { ref policy, .. } if policy == "static-tokens"),
            "unexpected error: {err:?}"
        );

        // Wrong token → same denial.
        let wrong = HttpEnvironmentStore::new(
            base.clone(),
            AuthMethod::Bearer("not-the-secret".to_string()),
        )
        .expect("client");
        let err = wrong
            .create_environment(&id, "local".to_string(), host_config("local"))
            .expect_err("unknown token must be denied");
        assert!(matches!(err, StoreError::Unauthorized { .. }));

        // The named operator deploys.
        let authed = HttpEnvironmentStore::new(base, AuthMethod::Bearer("e2e-secret".to_string()))
            .expect("client");
        let created = authed
            .create_environment(&id, "local".to_string(), host_config("local"))
            .expect("authorized create");
        assert_eq!(created.environment_id, id);
    })
    .await
    .expect("client task");
}
