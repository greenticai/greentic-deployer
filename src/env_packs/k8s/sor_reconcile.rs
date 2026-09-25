//! SoR-first reconcile (SoRLa storage phase 3, contract C3).
//!
//! Order, and why each step waits for the one before it:
//! 1. the env-level set MINUS its Deployments (namespace, secrets, config
//!    maps, policies) — everything a SoR pod or its registry pull needs;
//! 2. the SoR NetworkPolicies and each unit's Secret, Deployment and Service;
//! 3. wait for every SoR Deployment to be Available — a SoR that does not
//!    come up fails the reconcile before any flow or worker changes;
//! 4. write each route document into the env's store (bare name only, C1),
//!    delete the documents of retired SoRs, and delete the store keys of any
//!    input a retired or re-pointed unit used to read (on a Vault env, which
//!    cannot declare units, only the deletes run);
//! 5. the WHOLE desired state rendered from the refreshed dev-store seed, so
//!    the router and every worker roll onto a seed that holds the documents;
//! 6. prune: absent revisions, retired SoR units (in the namespace they were
//!    applied in), and the SoR policies once the last unit is gone.
//!
//! Nothing this module returns or reports carries a value: the SoR Secret's
//! contents and the route documents travel only through the cluster and the
//! [`SorRoutePublisher`]; the report holds [`ObjectRef`]s and
//! [`SorUnitStatus`] (names and an in-cluster URL).

use std::time::Duration;

use greentic_deploy_spec::Environment;
use serde_json::Value;

use super::K8sDeployerHandler;
use super::cluster::ObjectRef;
use super::deployer::{
    ReconcileReport, is_cluster_scoped, params_from_answers, provider, wait_for_worker_rollout,
};
use super::manifests::sor::{
    SorUnitInputs, render_sor_manifests, render_sor_network_policies, route_document,
    sor_object_name, sor_object_refs, sor_policy_refs, sor_service_url,
};
use super::manifests::{SecretsBackend, render_environment_manifests};
use crate::env_packs::deployer::DeployerError;
use crate::environment::sor_units::{AppliedSorUnit, SorUnit};
use crate::runtime_secrets::SecretValue;

/// Env override (whole seconds) for how long a SoR Deployment may take to
/// become Available: pulling its pack and reaching Postgres happen at boot.
pub const SOR_READY_TIMEOUT_ENV: &str = "GREENTIC_K8S_SOR_READY_TIMEOUT_SECS";
const SOR_READY_TIMEOUT: Duration = Duration::from_secs(300);
const SOR_READY_POLL_INTERVAL: Duration = Duration::from_secs(2);

fn sor_ready_timeout() -> Duration {
    std::env::var(SOR_READY_TIMEOUT_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(SOR_READY_TIMEOUT)
}

/// A declared unit with its decrypted inputs.
#[derive(Debug, Clone)]
pub struct SorUnitRender {
    pub unit: SorUnit,
    pub inputs: SorUnitInputs,
}

/// One route document to write at `default/_/sorla/<sor>`.
#[derive(Debug, Clone)]
pub struct RouteDocument {
    pub sor: String,
    pub value: SecretValue,
}

/// The store side of step 4. Implemented by the CLI (which owns the store);
/// errors are operator prose and must never contain a value.
pub trait SorRoutePublisher: Send + Sync {
    /// Write every route document (bare name), then [`Self::retire`], and
    /// return the env's dev-store seed as it stands after both (base64).
    ///
    /// `None` means "there is no store file" and renders an EMPTY dev-store
    /// Secret — it never means "nothing changed". An implementation that
    /// skipped every write must still return `Some(seed)` when the file exists.
    fn publish(
        &self,
        routes: &[RouteDocument],
        retired_sors: &[String],
        stale_input_refs: &[String],
    ) -> Result<Option<String>, String>;

    /// Delete the route documents of `retired_sors` and the store keys named
    /// by `stale_input_refs` (rel-paths no declared unit reads any more). A
    /// key that is already absent is not an error. Writes nothing.
    fn retire(&self, retired_sors: &[String], stale_input_refs: &[String]) -> Result<(), String>;
}

/// Everything the SoR reconcile needs beyond the env and its answers.
pub struct SorReconcile<'a> {
    pub units: &'a [SorUnitRender],
    /// Units applied earlier that the manifest no longer declares.
    pub retired_units: &'a [AppliedSorUnit],
    /// SoR keys no declared unit claims any more.
    pub retired_sors: &'a [String],
    /// Input rel-paths a retired or re-pointed unit used to read that no
    /// declared unit reads now: deleted from the store in step 4.
    pub stale_input_refs: &'a [String],
    /// Stale input rel-paths outside their unit's own `sor-<unit_id>/`
    /// segment: left in place and surfaced in the report by path only.
    pub skipped_input_refs: &'a [String],
    pub publisher: &'a dyn SorRoutePublisher,
}

/// One entry of the reconcile report's `sor_units`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SorUnitStatus {
    pub unit_id: String,
    pub sor: String,
    pub service: String,
    pub url: String,
    pub ready: bool,
}

fn push_unique(applied: &mut Vec<ObjectRef>, object: ObjectRef) {
    if !applied.contains(&object) {
        applied.push(object);
    }
}

fn is_deployment(manifest: &Value) -> bool {
    manifest.get("kind").and_then(Value::as_str) == Some("Deployment")
}

impl K8sDeployerHandler {
    /// [`Self::reconcile`] for an env that declares (or used to declare) SoR
    /// units — see the module doc for the order and why it matters.
    pub async fn reconcile_with_sor(
        &self,
        env: &Environment,
        answers: Option<&Value>,
        manage_namespace: bool,
        sor: &SorReconcile<'_>,
    ) -> Result<ReconcileReport, DeployerError> {
        self.reconcile_with_sor_timed(
            env,
            answers,
            manage_namespace,
            sor,
            sor_ready_timeout(),
            SOR_READY_POLL_INTERVAL,
        )
        .await
    }

    pub(crate) async fn reconcile_with_sor_timed(
        &self,
        env: &Environment,
        answers: Option<&Value>,
        manage_namespace: bool,
        sor: &SorReconcile<'_>,
        ready_timeout: Duration,
        poll_interval: Duration,
    ) -> Result<ReconcileReport, DeployerError> {
        // Amendment 6: route documents reach workers through the dev-store
        // seed, which a Vault env does not ship. Refuse before any cluster
        // call rather than bring up a SoR no worker can find.
        if !sor.units.is_empty() && matches!(self.secrets_backend, SecretsBackend::Vault(_)) {
            return Err(DeployerError::Provider(
                "SoR units need the dev-store secrets backend; this environment's secrets \
                 pack is Vault, so nothing was applied"
                    .to_string(),
            ));
        }
        let mut params = params_from_answers(env, answers)?;
        params.dev_secrets_data = self.dev_secrets_data.clone();
        params.secrets_backend = self.secrets_backend.clone();
        let keep = |m: &Value| manage_namespace || !is_cluster_scoped(m);
        let mut applied = Vec::new();

        // 1. env-level set minus Deployments.
        for manifest in render_environment_manifests(env, &params)
            .iter()
            .filter(|m| keep(m) && !is_deployment(m))
        {
            self.cluster.apply(manifest).await.map_err(provider)?;
            push_unique(
                &mut applied,
                ObjectRef::from_manifest(manifest).map_err(provider)?,
            );
        }

        // 2. SoR policies + objects.
        let mut sor_objects = Vec::new();
        if !sor.units.is_empty() {
            sor_objects.extend(render_sor_network_policies(env, &params));
        }
        for render in sor.units {
            sor_objects.extend(render_sor_manifests(
                env,
                &render.unit,
                &render.inputs,
                &params,
            ));
        }
        for manifest in &sor_objects {
            self.cluster.apply(manifest).await.map_err(provider)?;
            push_unique(
                &mut applied,
                ObjectRef::from_manifest(manifest).map_err(provider)?,
            );
        }

        // 3. every SoR Available before anything reads its route document.
        for render in sor.units {
            let deployment = ObjectRef {
                api_version: "apps/v1".into(),
                kind: "Deployment".into(),
                namespace: Some(params.namespace.clone()),
                name: sor_object_name(&render.unit.unit_id),
            };
            wait_for_worker_rollout(
                self.cluster.as_ref(),
                &deployment,
                1,
                ready_timeout,
                poll_interval,
            )
            .await
            .map_err(|e| {
                let reason = match e {
                    DeployerError::Provider(msg) => msg,
                    other => other.to_string(),
                };
                DeployerError::Provider(format!(
                    "SoR unit `{}` did not become Available, so no router or worker \
                     Deployment was rolled: {reason}",
                    render.unit.unit_id
                ))
            })?;
        }

        // 4. route documents.
        let routes: Vec<RouteDocument> = sor
            .units
            .iter()
            .map(|r| RouteDocument {
                sor: r.unit.sor.clone(),
                value: route_document(&r.unit, &r.inputs, &params.namespace),
            })
            .collect();
        let fresh_seed = if matches!(self.secrets_backend, SecretsBackend::Vault(_)) {
            // Retire-only (units on Vault were refused above): nothing to
            // write into a dev store, and no refreshed seed to ship. The
            // deletes still run so a retired unit's inputs do not linger;
            // absent keys are fine.
            sor.publisher
                .retire(sor.retired_sors, sor.stale_input_refs)
                .map_err(|e| {
                    DeployerError::Provider(format!("retiring the SoR store entries: {e}"))
                })?;
            self.dev_secrets_data.clone()
        } else {
            sor.publisher
                .publish(&routes, sor.retired_sors, sor.stale_input_refs)
                .map_err(|e| {
                    DeployerError::Provider(format!("writing the SoR route documents: {e}"))
                })?
        };

        // 5. the whole desired state, from the refreshed seed.
        let desired = self
            .render_environment_with_dev_secrets(env, answers, fresh_seed)
            .map_err(|e| DeployerError::Provider(e.to_string()))?;
        for manifest in desired.iter().filter(|m| keep(m)) {
            self.cluster.apply(manifest).await.map_err(provider)?;
            push_unique(
                &mut applied,
                ObjectRef::from_manifest(manifest).map_err(provider)?,
            );
        }

        // 6. prune.
        let mut pruned = self.prune_absent(env, &params).await?;
        for retired in sor.retired_units {
            for object in sor_object_refs(&retired.unit_id, &retired.namespace) {
                self.cluster.delete(&object).await.map_err(provider)?;
                pruned.push(object);
            }
        }
        if sor.units.is_empty() && !sor.retired_units.is_empty() {
            for object in sor_policy_refs(&params.namespace) {
                self.cluster.delete(&object).await.map_err(provider)?;
                pruned.push(object);
            }
        }

        let router_address = self.read_router_address(env, &params).await;
        let sor_units = sor
            .units
            .iter()
            .map(|r| SorUnitStatus {
                unit_id: r.unit.unit_id.clone(),
                sor: r.unit.sor.clone(),
                service: sor_object_name(&r.unit.unit_id),
                url: sor_service_url(&r.unit.unit_id, &params.namespace),
                ready: true,
            })
            .collect();
        Ok(ReconcileReport {
            applied,
            pruned,
            router_address,
            sor_units,
            sor_skipped_input_refs: sor.skipped_input_refs.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use async_trait::async_trait;
    use greentic_deploy_spec::CapabilitySlot;
    use serde_json::Value;

    use super::*;
    use crate::env_packs::deployer::conformance::build_fixture_env;
    use crate::env_packs::k8s::cluster::{
        K8sCluster, K8sClusterError, RolloutStatus, ServiceStatus,
    };
    use crate::env_packs::k8s::manifests::sor::tests::{inputs, unit};
    use crate::env_packs::k8s::manifests::{DEV_SECRETS_SECRET_NAME, K8sParams};

    type Log = Arc<Mutex<Vec<String>>>;
    /// One `publish` call: `(sor, route document)` pairs, the retired SoRs,
    /// then the stale input refs.
    type PublishCall = (Vec<(String, String)>, Vec<String>, Vec<String>);

    /// Records every apply/delete in order; Deployments named in `never_ready`
    /// never report an available replica.
    #[derive(Debug, Default)]
    struct OrderedCluster {
        log: Log,
        objects: Mutex<BTreeMap<ObjectRef, Value>>,
        never_ready: BTreeSet<String>,
    }

    #[async_trait]
    impl K8sCluster for OrderedCluster {
        async fn apply(&self, manifest: &Value) -> Result<(), K8sClusterError> {
            let o = ObjectRef::from_manifest(manifest)?;
            self.log
                .lock()
                .unwrap()
                .push(format!("apply {}/{}", o.kind, o.name));
            self.objects.lock().unwrap().insert(o, manifest.clone());
            Ok(())
        }
        async fn delete(&self, o: &ObjectRef) -> Result<(), K8sClusterError> {
            self.log
                .lock()
                .unwrap()
                .push(format!("delete {}/{}", o.kind, o.name));
            self.objects.lock().unwrap().remove(o);
            Ok(())
        }
        async fn get_rollout_status(
            &self,
            d: &ObjectRef,
        ) -> Result<RolloutStatus, K8sClusterError> {
            let available = if self.never_ready.contains(&d.name) {
                0
            } else {
                1
            };
            Ok(RolloutStatus {
                generation: 1,
                observed_generation: Some(1),
                replicas: 1,
                updated_replicas: 1,
                available_replicas: available,
            })
        }
        async fn get_service_status(
            &self,
            _s: &ObjectRef,
        ) -> Result<ServiceStatus, K8sClusterError> {
            unreachable!("a ClusterIP env never reads its router Service")
        }
    }

    struct RecordingPublisher {
        log: Log,
        calls: Mutex<Vec<PublishCall>>,
        fresh: Option<String>,
    }

    impl SorRoutePublisher for RecordingPublisher {
        fn publish(
            &self,
            routes: &[RouteDocument],
            retired: &[String],
            stale: &[String],
        ) -> Result<Option<String>, String> {
            self.log.lock().unwrap().push("publish".into());
            self.calls.lock().unwrap().push((
                routes
                    .iter()
                    .map(|r| (r.sor.clone(), r.value.expose().to_string()))
                    .collect(),
                retired.to_vec(),
                stale.to_vec(),
            ));
            Ok(self.fresh.clone())
        }

        fn retire(&self, retired: &[String], stale: &[String]) -> Result<(), String> {
            self.log.lock().unwrap().push("retire".into());
            self.calls
                .lock()
                .unwrap()
                .push((Vec::new(), retired.to_vec(), stale.to_vec()));
            Ok(())
        }
    }

    fn env_with_dev_store() -> greentic_deploy_spec::Environment {
        let mut env = build_fixture_env();
        env.packs.push(crate::cli::tests_common::make_binding(
            CapabilitySlot::Secrets,
            "greentic.secrets.dev-store@1.0.0",
        ));
        env
    }

    fn fixture(
        never_ready: &[&str],
    ) -> (
        K8sDeployerHandler,
        Arc<OrderedCluster>,
        RecordingPublisher,
        Log,
    ) {
        let log: Log = Arc::default();
        let cluster = Arc::new(OrderedCluster {
            log: log.clone(),
            never_ready: never_ready.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        });
        let handler = K8sDeployerHandler::with_cluster_and_dev_secrets(
            cluster.clone(),
            Some("c3RhbGU=".into()),
        );
        let publisher = RecordingPublisher {
            log: log.clone(),
            calls: Mutex::default(),
            fresh: Some("ZnJlc2g=".into()),
        };
        (handler, cluster, publisher, log)
    }

    fn position(log: &[String], needle: &str) -> usize {
        log.iter()
            .position(|e| e.starts_with(needle))
            .unwrap_or_else(|| panic!("`{needle}` not in {log:?}"))
    }

    #[tokio::test]
    async fn sor_units_come_up_and_publish_before_any_worker_or_router_is_applied() {
        let (handler, cluster, publisher, log) = fixture(&[]);
        let env = env_with_dev_store();
        let units = [SorUnitRender {
            unit: unit(),
            inputs: inputs(false),
        }];
        let sor = SorReconcile {
            units: &units,
            retired_units: &[],
            retired_sors: &[],
            stale_input_refs: &[],
            skipped_input_refs: &[],
            publisher: &publisher,
        };
        let report = handler
            .reconcile_with_sor_timed(
                &env,
                None,
                true,
                &sor,
                Duration::from_secs(10),
                Duration::from_millis(1),
            )
            .await
            .expect("reconcile");
        let log = log.lock().unwrap().clone();
        let sor_deployment = position(&log, "apply Deployment/gtc-sor-landlord");
        let published = position(&log, "publish");
        assert!(sor_deployment < published);
        assert!(
            published < position(&log, "apply Deployment/gtc-worker-"),
            "{log:?}"
        );
        assert!(
            published < position(&log, "apply Deployment/gtc-router"),
            "{log:?}"
        );
        assert!(position(&log, "apply NetworkPolicy/gtc-allow-worker-to-sor") < published);

        let params = K8sParams::for_env(&env);
        let dev_secret = cluster
            .objects
            .lock()
            .unwrap()
            .get(&ObjectRef {
                api_version: "v1".into(),
                kind: "Secret".into(),
                namespace: Some(params.namespace.clone()),
                name: DEV_SECRETS_SECRET_NAME.into(),
            })
            .cloned()
            .unwrap();
        assert_eq!(
            dev_secret.pointer("/data/.dev.secrets.env").unwrap(),
            "ZnJlc2g=",
            "workers get the seed as it stands AFTER the route documents were written"
        );

        assert_eq!(
            report.sor_units,
            vec![SorUnitStatus {
                unit_id: "landlord".into(),
                sor: "landlord-tenant-sor".into(),
                service: "gtc-sor-landlord".into(),
                url: format!(
                    "http://gtc-sor-landlord.{}.svc.cluster.local:8787",
                    params.namespace
                ),
                ready: true,
            }]
        );
        let unique: BTreeSet<_> = report.applied.iter().collect();
        assert_eq!(
            unique.len(),
            report.applied.len(),
            "each object is reported once"
        );
        let calls = publisher.calls.lock().unwrap();
        let doc: Value = serde_json::from_str(&calls[0].0[0].1).unwrap();
        assert_eq!(calls[0].0[0].0, "landlord-tenant-sor");
        assert_eq!(doc["tenant"], "acme");
    }

    #[tokio::test(start_paused = true)]
    async fn a_sor_unit_that_never_becomes_available_fails_before_any_worker_changes() {
        let (handler, _cluster, publisher, log) = fixture(&["gtc-sor-landlord"]);
        let env = env_with_dev_store();
        let units = [SorUnitRender {
            unit: unit(),
            inputs: inputs(false),
        }];
        let sor = SorReconcile {
            units: &units,
            retired_units: &[],
            retired_sors: &[],
            stale_input_refs: &[],
            skipped_input_refs: &[],
            publisher: &publisher,
        };
        let err = handler
            .reconcile_with_sor_timed(
                &env,
                None,
                true,
                &sor,
                Duration::from_secs(10),
                Duration::from_secs(2),
            )
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("SoR unit `landlord` did not become Available"),
            "{msg}"
        );
        let log = log.lock().unwrap().clone();
        assert!(
            !log.iter()
                .any(|e| e.starts_with("apply Deployment/gtc-worker-")),
            "{log:?}"
        );
        assert!(
            !log.iter()
                .any(|e| e.starts_with("apply Deployment/gtc-router")),
            "{log:?}"
        );
        assert!(
            !log.iter().any(|e| e == "publish"),
            "no route document for a SoR that is not up"
        );
        assert!(!msg.contains("shared-SECRET-token") && !msg.contains("pw-SECRET"));
    }

    #[tokio::test]
    async fn a_retired_sor_unit_is_pruned_with_its_policies_and_route_document() {
        let (handler, cluster, publisher, log) = fixture(&[]);
        let env = env_with_dev_store();
        let retired = [AppliedSorUnit {
            unit_id: "landlord".into(),
            sor: "landlord-tenant-sor".into(),
            namespace: "gtc-old".into(),
            input_refs: vec!["default/_/sor-landlord/postgres_url".into()],
        }];
        let retired_sors = ["landlord-tenant-sor".to_string()];
        let stale = ["default/_/sor-landlord/postgres_url".to_string()];
        let sor = SorReconcile {
            units: &[],
            retired_units: &retired,
            retired_sors: &retired_sors,
            stale_input_refs: &stale,
            skipped_input_refs: &[],
            publisher: &publisher,
        };
        let report = handler
            .reconcile_with_sor_timed(
                &env,
                None,
                true,
                &sor,
                Duration::from_secs(10),
                Duration::from_millis(1),
            )
            .await
            .expect("reconcile");
        let log = log.lock().unwrap().clone();
        for kind in ["Deployment", "Service", "Secret"] {
            assert!(
                log.contains(&format!("delete {kind}/gtc-sor-landlord")),
                "{log:?}"
            );
            assert!(
                report.pruned.iter().any(|o| o.kind == kind
                    && o.name == "gtc-sor-landlord"
                    && o.namespace.as_deref() == Some("gtc-old")),
                "pruned in the namespace it was applied in"
            );
        }
        assert!(log.contains(&"delete NetworkPolicy/gtc-allow-worker-to-sor".to_string()));
        assert_eq!(
            publisher.calls.lock().unwrap()[0].1,
            vec!["landlord-tenant-sor".to_string()]
        );
        assert_eq!(
            publisher.calls.lock().unwrap()[0].2,
            stale.to_vec(),
            "a retired unit's inputs are deleted from the store"
        );
        assert!(report.sor_units.is_empty());
        assert!(
            !cluster
                .objects
                .lock()
                .unwrap()
                .keys()
                .any(|o| o.name.starts_with("gtc-sor-"))
        );
    }

    #[tokio::test]
    async fn the_report_never_carries_a_secret_and_omits_sor_units_when_there_are_none() {
        let (handler, _cluster, publisher, _log) = fixture(&[]);
        let env = env_with_dev_store();
        let units = [SorUnitRender {
            unit: unit(),
            inputs: inputs(true),
        }];
        let sor = SorReconcile {
            units: &units,
            retired_units: &[],
            retired_sors: &[],
            stale_input_refs: &[],
            skipped_input_refs: &[],
            publisher: &publisher,
        };
        let report = handler
            .reconcile_with_sor_timed(
                &env,
                None,
                true,
                &sor,
                Duration::from_secs(10),
                Duration::from_millis(1),
            )
            .await
            .unwrap();
        let text = serde_json::to_string(&report).unwrap();
        for leaked in ["shared-SECRET-token", "pw-SECRET", "CA-SECRET"] {
            assert!(!text.contains(leaked), "report must not carry `{leaked}`");
        }
        // The SoR Secret carries its values base64-encoded (`data`); the report
        // must not carry that encoding either — it holds only object refs.
        use base64::Engine as _;
        for leaked in ["shared-SECRET-token", "postgres://u:pw-SECRET@db:5432/sor"] {
            let b64 = base64::engine::general_purpose::STANDARD.encode(leaked);
            assert!(
                !text.contains(&b64),
                "report must not carry base64 of `{leaked}`"
            );
        }
        assert!(
            !text.contains("\"data\""),
            "no manifest body in the report: {text}"
        );
        let plain = handler.reconcile(&env, None, true).await.unwrap();
        assert!(
            serde_json::to_value(&plain)
                .unwrap()
                .get("sor_units")
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_vault_env_with_sor_units_is_refused_before_any_cluster_call() {
        let (_h, cluster, publisher, log) = fixture(&[]);
        let handler = K8sDeployerHandler::with_cluster(cluster.clone()).with_secrets_backend(
            crate::env_packs::k8s::manifests::SecretsBackend::Vault(
                crate::env_packs::k8s::manifests::VaultBackend {
                    addr: "http://vault.vault.svc:8200".to_string(),
                    k8s_role: "greentic-worker".to_string(),
                    kv_mount: "secret".to_string(),
                    kv_prefix: "greentic".to_string(),
                    auth_mount: "kubernetes".to_string(),
                    transit_mount: "transit".to_string(),
                    transit_key: "greentic".to_string(),
                    namespace: None,
                },
            ),
        );
        let env = env_with_dev_store();
        let units = [SorUnitRender {
            unit: unit(),
            inputs: inputs(false),
        }];
        let sor = SorReconcile {
            units: &units,
            retired_units: &[],
            retired_sors: &[],
            stale_input_refs: &[],
            skipped_input_refs: &[],
            publisher: &publisher,
        };
        let err = handler
            .reconcile_with_sor_timed(
                &env,
                None,
                true,
                &sor,
                Duration::from_secs(10),
                Duration::from_millis(1),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("dev-store"), "{err}");
        assert!(
            log.lock().unwrap().is_empty(),
            "no cluster call and no publish"
        );
    }

    /// Retiring units on a Vault env must not wedge it: no dev-store write,
    /// the objects are pruned, and the handler's own seed ships unchanged.
    #[tokio::test]
    async fn a_vault_env_retiring_its_units_prunes_them_without_publishing() {
        let (_h, cluster, publisher, log) = fixture(&[]);
        let handler = K8sDeployerHandler::with_cluster_and_dev_secrets(
            cluster.clone(),
            Some("c3RhbGU=".into()),
        )
        .with_secrets_backend(crate::env_packs::k8s::manifests::SecretsBackend::Vault(
            crate::env_packs::k8s::manifests::VaultBackend {
                addr: "http://vault.vault.svc:8200".to_string(),
                k8s_role: "greentic-worker".to_string(),
                kv_mount: "secret".to_string(),
                kv_prefix: "greentic".to_string(),
                auth_mount: "kubernetes".to_string(),
                transit_mount: "transit".to_string(),
                transit_key: "greentic".to_string(),
                namespace: None,
            },
        ));
        let env = env_with_dev_store();
        let retired = [AppliedSorUnit {
            unit_id: "landlord".into(),
            sor: "landlord-tenant-sor".into(),
            namespace: "gtc-old".into(),
            input_refs: vec![],
        }];
        let retired_sors = ["landlord-tenant-sor".to_string()];
        let sor = SorReconcile {
            units: &[],
            retired_units: &retired,
            retired_sors: &retired_sors,
            stale_input_refs: &[],
            skipped_input_refs: &[],
            publisher: &publisher,
        };
        handler
            .reconcile_with_sor_timed(
                &env,
                None,
                true,
                &sor,
                Duration::from_secs(10),
                Duration::from_millis(1),
            )
            .await
            .expect("a retire-only reconcile on Vault succeeds");
        let log = log.lock().unwrap().clone();
        assert!(!log.iter().any(|e| e == "publish"), "{log:?}");
        assert!(log.iter().any(|e| e == "retire"), "{log:?}");
        assert!(log.contains(&"delete Deployment/gtc-sor-landlord".to_string()));
    }
}
