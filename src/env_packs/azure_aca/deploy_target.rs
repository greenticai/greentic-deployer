//! The side-effect seam the Container Apps verbs drive (the Azure twin of
//! `EcsDeployTarget`). The in-memory fake lives in `fake.rs`; the ARM REST client
//! in `real_target.rs` (behind `deploy-azure-aca`).

use std::fmt::Debug;

use async_trait::async_trait;

use super::arm_types::{AppSecret, AppSpec, TrafficEntry};
use super::revision_intent::LiveIntent;

/// Which Container App (scope is fixed by the target at construction).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct AppRef {
    pub name: String,
}

/// One ACA revision of an app.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RevisionRef {
    pub app: AppRef,
    /// Full revision name `<app>--<suffix>`.
    pub name: String,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum AcaTargetError {
    #[error("Container Apps request failed: {0}")]
    Api(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("{0}")]
    Unavailable(String),
}

/// What exists for an app, read before any write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AppState {
    Absent,
    Present {
        /// Value of the `greentic:owner` tag, if any.
        owner: Option<String>,
        /// Current `ingress.traffic` (full revision names, whole percents).
        traffic: Vec<TrafficEntry>,
    },
}

/// Revision health as the platform reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RevisionStatus {
    Provisioning,
    Running { replicas: u32 },
    Failed { reason: String },
    Inactive,
    Absent,
}

#[async_trait]
pub(crate) trait AcaDeployTarget: Debug + Send + Sync {
    /// Read the app: absent, or its owner tag and traffic.
    async fn inspect_app(&self, app: &AppRef) -> Result<AppState, AcaTargetError>;

    /// Secrets of an existing app WITH values (`listSecrets`); empty when absent.
    async fn list_secrets(&self, app: &AppRef) -> Result<Vec<AppSecret>, AcaTargetError>;

    /// Create or update the app with a new revision (one PUT). Idempotent per
    /// revision name only when the caller checked the intent first.
    async fn put_revision(&self, spec: &AppSpec) -> Result<RevisionRef, AcaTargetError>;

    /// The intent stamped on a revision.
    async fn live_revision_intent(&self, rev: &RevisionRef) -> Result<LiveIntent, AcaTargetError>;

    async fn revision_status(&self, rev: &RevisionRef) -> Result<RevisionStatus, AcaTargetError>;

    /// Rewrite `ingress.traffic` (creates no revision). Weights must sum to 100.
    async fn set_traffic(
        &self,
        app: &AppRef,
        weights: &[TrafficEntry],
    ) -> Result<(), AcaTargetError>;

    /// Deactivate a revision. Idempotent against an absent / inactive one.
    async fn deactivate_revision(&self, rev: &RevisionRef) -> Result<(), AcaTargetError>;

    /// Delete the app (and with it its revisions and secrets). `Ok(false)` when
    /// it did not exist.
    async fn delete_app(&self, app: &AppRef) -> Result<bool, AcaTargetError>;

    /// `https://<fqdn>` of the app's ingress, once it has one.
    async fn discover_endpoint(&self, app: &AppRef) -> Result<Option<String>, AcaTargetError>;
}

/// Default target of a handler with no live client wired: fails honestly.
#[derive(Debug, Default)]
pub(crate) struct UnconfiguredAcaTarget;

fn unconfigured<T>() -> Result<T, AcaTargetError> {
    Err(AcaTargetError::Unavailable(
        "no Azure Container Apps client is configured; build with the `deploy-azure-aca` feature \
         and bind a service principal"
            .to_string(),
    ))
}

#[async_trait]
impl AcaDeployTarget for UnconfiguredAcaTarget {
    async fn inspect_app(&self, _: &AppRef) -> Result<AppState, AcaTargetError> {
        unconfigured()
    }
    async fn list_secrets(&self, _: &AppRef) -> Result<Vec<AppSecret>, AcaTargetError> {
        unconfigured()
    }
    async fn put_revision(&self, _: &AppSpec) -> Result<RevisionRef, AcaTargetError> {
        unconfigured()
    }
    async fn live_revision_intent(&self, _: &RevisionRef) -> Result<LiveIntent, AcaTargetError> {
        unconfigured()
    }
    async fn revision_status(&self, _: &RevisionRef) -> Result<RevisionStatus, AcaTargetError> {
        unconfigured()
    }
    async fn set_traffic(&self, _: &AppRef, _: &[TrafficEntry]) -> Result<(), AcaTargetError> {
        unconfigured()
    }
    async fn deactivate_revision(&self, _: &RevisionRef) -> Result<(), AcaTargetError> {
        unconfigured()
    }
    async fn delete_app(&self, _: &AppRef) -> Result<bool, AcaTargetError> {
        unconfigured()
    }
    async fn discover_endpoint(&self, _: &AppRef) -> Result<Option<String>, AcaTargetError> {
        unconfigured()
    }
}
