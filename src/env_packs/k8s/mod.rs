//! K8s deployer env-pack (Phase D, K8s/Zain slice — PR-5.0 scaffold).
//!
//! Backs the `greentic.deployer.k8s@1.0.0` binding — the first
//! real-cloud proving ground of the next-gen deployment model. The
//! scaffold ships the full deterministic half of the slice; the typed
//! Kubernetes API client landed as [`kube_client`] (PR-5.2, `k8s-client`
//! feature) behind the seams defined here. `gtc op env reconcile` (PR-5.3)
//! constructs that client from the binding's answers and applies the
//! rendered desired state through it
//! ([`K8sDeployerHandler::reconcile`](deployer::K8sDeployerHandler::reconcile)).
//! `gtc op credentials requirements` now connects a live validator client
//! (the CLI's credentials path injects it via `K8sDeployerCredentials::with_client`)
//! and per-revision Deployer-verb dispatch (`op env apply-revision`) has
//! shipped; the live-cluster readiness wait is the remaining PR-5.3 slice.
//! Zain's infrastructure answers (`plans/zain-k8s-alignment.md`) gate the
//! real-cluster and production acceptance, not this scaffold — sandbox
//! defaults per that doc.
//!
//! ## Answers consumption
//!
//! `op env render` and `op env reconcile` read the binding's `answers_ref`
//! and feed it to [`K8sParams::from_answers`](manifests::K8sParams::from_answers)
//! so operator overrides (namespace, runtime image, router replicas) reach
//! the rendered manifests; reconcile additionally reads `kubeconfig_context`
//! to target the cluster. The per-revision Deployer verbs (`warm_revision`,
//! `archive_revision`, `apply_traffic_split`) take the binding's `answers`
//! as a trait parameter (PR-5.3) and feed the same `from_answers`
//! projection; `op env apply-revision` and `op credentials requirements`
//! resolve and thread it in.
//!
//! ## Operator CLI verb disclaimer
//!
//! `gtc op env reconcile` is the apply path: it constructs a connected
//! cluster client and creates / upserts / prunes cluster workloads. The
//! per-revision lifecycle verbs (`gtc op revision warm`, `gtc op traffic
//! set`, etc.) remain storage-layer only — they record desired state and
//! do not invoke `Deployer` impls, true for every registered deployer
//! (including AWS-ECS since C3). Per-revision Deployer-verb dispatch
//! (`op env apply-revision`) has shipped; the live-cluster readiness wait
//! is the remaining PR-5.3 slice.
//!
//! Module layout (mirrors the local-process / AWS-ECS reference shape):
//!
//! - `mod.rs` (this file) — the [`EnvPackHandler`] surface: slot,
//!   descriptor, versions, credentials accessor, wizard QASpec, and the
//!   [`as_deployer`](EnvPackHandler::as_deployer) seam.
//! - [`manifests`] — pure deterministic desired-state rendering (router +
//!   per-revision workers + runtime-config ConfigMap + NetworkPolicies,
//!   Restricted-profile hardened).
//! - [`cluster`] — the [`K8sCluster`] side-effect seam (`apply`/`delete`).
//!   Default is [`UnconfiguredCluster`]: provider verbs fail honestly
//!   until PR-5.3 binds a connected client.
//! - [`kube_client`] (`k8s-client` feature) — the production kube-rs
//!   impls of both client seams: [`KubeCluster`] (forced server-side
//!   apply + idempotent delete) and [`KubeValidatorClient`]
//!   (`SelfSubjectReview` / `SelfSubjectAccessReview` probes).
//! - [`deployer`] — `impl Deployer for K8sDeployerHandler`; passes
//!   [`run_conformance`](crate::env_packs::deployer::run_conformance)
//!   against an in-memory cluster fake.
//! - [`render`] — `impl ManifestRenderer for K8sDeployerHandler`; backs
//!   `gtc op env render` with the same rendering functions the
//!   [`deployer`] verbs apply (plan §6 step 10).
//! - [`credentials`] — `SelfSubjectAccessReview`-based
//!   [`DeployerCredentials`](crate::credentials::DeployerCredentials)
//!   (probes fail closed until the client ships; decision logic pinned
//!   by mock tests).
//! - [`bootstrap`] — minimum-privilege Namespace/ServiceAccount/Role/
//!   RoleBinding rules pack, derived from the same operations list the
//!   probes validate.

pub(crate) mod async_bridge;
pub mod bootstrap;
pub mod cluster;
pub mod credentials;
pub mod deployer;
#[cfg(feature = "k8s-client")]
pub mod kube_client;
pub mod manifests;
pub mod render;

use std::sync::Arc;

use greentic_deploy_spec::CapabilitySlot;
use semver::VersionReq;

use super::slot::EnvPackHandler;
use crate::tool_check::ToolCheck;

pub use cluster::{K8sCluster, K8sClusterError, ObjectRef, UnconfiguredCluster};
pub use credentials::{K8sDeployerCredentials, K8sValidatorClient};
pub use deployer::ReconcileReport;
#[cfg(feature = "k8s-client")]
pub use kube_client::{KubeCluster, KubeValidatorClient};

/// Native handler for the K8s deployer env-pack.
#[derive(Debug)]
pub struct K8sDeployerHandler {
    creds: K8sDeployerCredentials,
    /// Cluster side-effect seam the [`Deployer`](crate::env_packs::deployer::Deployer)
    /// verbs mutate through. Crate-visible so `deployer.rs` reaches it.
    pub(crate) cluster: Arc<dyn K8sCluster>,
}

impl Default for K8sDeployerHandler {
    fn default() -> Self {
        Self {
            creds: K8sDeployerCredentials::default(),
            cluster: Arc::new(UnconfiguredCluster),
        }
    }
}

impl K8sDeployerHandler {
    /// Version-independent descriptor path used as the registry key.
    /// Matches `greentic.deployer.k8s@1.0.0` from the Phase D plan §6.
    pub const DESCRIPTOR_PATH: &'static str = "greentic.deployer.k8s";

    /// Descriptor versions this handler implements. Accepts the eventual
    /// `1.0.0` GA release and the scaffold-era dev pre-releases (same
    /// range shape as the AWS-ECS handler).
    pub const VERSION_REQ: &'static str = ">=1.0.0-dev, <2.0.0";

    /// Construct with a pluggable cluster seam. Tests pass the in-memory
    /// fake; the PR-5.3 orchestration wiring passes a connected
    /// [`KubeCluster`].
    pub fn with_cluster(cluster: Arc<dyn K8sCluster>) -> Self {
        Self {
            creds: K8sDeployerCredentials::default(),
            cluster,
        }
    }
}

impl EnvPackHandler for K8sDeployerHandler {
    fn slot(&self) -> CapabilitySlot {
        CapabilitySlot::Deployer
    }

    fn descriptor_path(&self) -> &str {
        Self::DESCRIPTOR_PATH
    }

    fn supported_versions(&self) -> VersionReq {
        Self::VERSION_REQ
            .parse()
            .expect("k8s version-req is valid (guarded by tests)")
    }

    fn preflight(&self) -> Vec<ToolCheck> {
        // Cluster mutation goes through the typed API seam
        // ([`kube_client::KubeCluster`]), not a `kubectl` shell-out
        // (plan §6 step 9), so no external tool is mandatory. If a later
        // PR adds an optional kubectl fallback adapter, its ToolCheck
        // surfaces here.
        Vec::new()
    }

    fn deployer_credentials(&self) -> Option<&dyn crate::credentials::DeployerCredentials> {
        Some(&self.creds)
    }

    fn wizard_qaspec_yaml(&self) -> Option<&'static str> {
        Some(include_str!("wizard.qaspec.yaml"))
    }

    fn as_deployer(&self) -> Option<&dyn crate::env_packs::deployer::Deployer> {
        Some(self)
    }

    fn as_manifest_renderer(&self) -> Option<&dyn crate::env_packs::render::ManifestRenderer> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_deploy_spec::PackDescriptor;

    #[test]
    fn handler_serves_deployer_slot_with_k8s_path() {
        let h = K8sDeployerHandler::default();
        assert_eq!(h.slot(), CapabilitySlot::Deployer);
        assert_eq!(h.descriptor_path(), "greentic.deployer.k8s");
        let _ = h.supported_versions();
    }

    #[test]
    fn version_req_accepts_ga_and_dev_releases() {
        let h = K8sDeployerHandler::default();
        let req = h.supported_versions();
        let ga = PackDescriptor::try_new("greentic.deployer.k8s@1.0.0").unwrap();
        assert!(req.matches(&ga.version().0), "{req} must accept 1.0.0");
        let dev = PackDescriptor::try_new("greentic.deployer.k8s@1.0.0-dev.1").unwrap();
        assert!(
            req.matches(&dev.version().0),
            "{req} must accept dev pre-release"
        );
        let next_major = PackDescriptor::try_new("greentic.deployer.k8s@2.0.0").unwrap();
        assert!(
            !req.matches(&next_major.version().0),
            "{req} must reject 2.0.0 (breaking bump)"
        );
    }

    #[test]
    fn exposes_credentials_contract_and_deployer_impl() {
        let h = K8sDeployerHandler::default();
        let creds = h
            .deployer_credentials()
            .expect("k8s handler must expose credentials");
        assert!(creds.requires_credentials_material());
        // The second half of the Phase D pluggability contract.
        assert!(
            (&h as &dyn EnvPackHandler).as_deployer().is_some(),
            "EnvPackHandler::as_deployer must surface the K8s Deployer impl"
        );
    }

    /// C6: pins this handler's wizard YAML to its canonical `id`.
    /// (Round-trip `qa_spec::FormSpec` deserialization is covered by the
    /// registry-level parametrized test in `registry.rs`.)
    #[test]
    fn wizard_qaspec_yaml_id_matches_canonical() {
        let yaml = K8sDeployerHandler::default()
            .wizard_qaspec_yaml()
            .expect("k8s handler ships a wizard QASpec");
        let spec: qa_spec::FormSpec =
            serde_yaml_bw::from_str(yaml).expect("wizard.qaspec.yaml parses as FormSpec");
        assert_eq!(spec.id, "greentic.deployer.k8s.wizard");
    }
}
