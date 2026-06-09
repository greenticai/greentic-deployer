//! Deployer-slot contract (Phase D §6 step 2).
//!
//! Every deployer env-pack — the local-process reference impl, the K8s
//! slice (Zain ship gate), AWS-ECS, GCP Cloud Run, Azure Container Apps,
//! Single-VM — implements the same [`Deployer`] trait. The
//! [`run_conformance`] black-box test bench runs against any impl: a new
//! deployer ships its trait impl, calls `run_conformance` from a single
//! integration test, and either passes or surfaces a structured failure
//! against the contract.
//!
//! The trait deliberately models **provider-side effects**, not the
//! lifecycle state matrix — the matrix lives in
//! [`crate::environment::lifecycle`] and is shared by every deployer
//! through the storage layer. A deployer's job is to make the provider
//! reality match the env's recorded intent (create the K8s Deployment,
//! mint the ECS task-set, …); the env's `Revision.lifecycle` is then
//! advanced by the operator CLI via `apply_revision_transition`. Keeping
//! these orthogonal means K8s + AWS impls don't reimplement state
//! mutation and the conformance suite stays storage-agnostic.
//!
//! ## Module layout
//!
//! - [`trait_def`] — the [`Deployer`] trait + [`DeployerError`] +
//!   per-verb outcome types.
//! - [`conformance`] — [`run_conformance`]: the bench K8s/AWS slices
//!   call from their own integration tests.

pub mod conformance;
pub mod trait_def;

pub use conformance::{ConformanceFailure, run_conformance};
pub use trait_def::{
    ArchiveOutcome, Deployer, DeployerError, DrainOutcome, StageOutcome, TrafficSplitOutcome,
    WarmOutcome,
};
