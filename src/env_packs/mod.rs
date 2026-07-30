//! Env-pack registry: binds a [`PackDescriptor`](greentic_deploy_spec::PackDescriptor)
//! `kind` to a native capability handler (`A9`).
//!
//! - [`slot`] — the [`EnvPackHandler`](slot::EnvPackHandler) trait and the
//!   built-in, metadata-only handlers for the five default `local` bindings.
//! - [`registry`] — [`EnvPackRegistry`](registry::EnvPackRegistry): built-in
//!   registrations plus the Phase D plug-in `register` hook.

#[cfg(feature = "creds-aws")]
pub mod aws;
pub mod deployer;
#[cfg(feature = "creds-gcp")]
pub mod gcp_cloudrun;
pub mod k8s;
pub mod local_process;
pub mod registry;
pub mod render;
pub mod slot;

#[cfg(feature = "creds-aws")]
pub use aws::{AwsDeployerCredentials, AwsEcsDeployerHandler, AwsValidatorClient};
#[cfg(feature = "creds-gcp")]
pub use gcp_cloudrun::{GcpCloudRunDeployerHandler, GcpDeployerCredentials, GcpValidatorClient};
pub use k8s::{K8sDeployerCredentials, K8sDeployerHandler, K8sValidatorClient};
pub use local_process::{LocalProcessCredentials, LocalProcessDeployerHandler};
pub use registry::{EnvPackRegistry, RegistryError};
pub use render::ManifestRenderer;
pub use slot::{BUILTIN_HANDLERS, BuiltinHandler, EnvPackHandler};
