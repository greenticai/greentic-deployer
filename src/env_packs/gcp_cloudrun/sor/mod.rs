//! SoR units on Cloud Run (SoRLa phase 3E).
//!
//! One Cloud Run service `gtc-sor-<unit_id>` runs greentic-sorx per declared
//! unit, pulling its pack at boot with the runtime service account's
//! metadata-server token (E2) and storing into the operator's Postgres (E1).
//! Its inputs are versions of ONE owner-stamped Secret Manager secret,
//! `<secret_prefix>-sor-<unit_id>`, staged through the existing
//! [`CloudRunTarget`](super::deploy_target::CloudRunTarget) seam; the service
//! itself goes through [`target::SorServiceTarget`], a separate seam because a
//! SoR service is addressed by NAME, while every worker service is addressed by
//! `DeploymentId`.
//!
//! Policy lives in [`up`] and [`retire`]; [`spec`] is pure; [`real`] only
//! translates to Google APIs. Nothing here ever carries an input value outside
//! a Secret Manager payload or the route document.

pub mod fake;
// `real` is created in Task 8; `deploy-gcp-cloudrun` is default-on, so leaving
// this uncommented before the file exists breaks a plain `cargo build`.
// #[cfg(feature = "deploy-gcp-cloudrun")]
// pub mod real;
// pub mod retire;
// pub mod spec;
pub mod target;
// pub mod up;
