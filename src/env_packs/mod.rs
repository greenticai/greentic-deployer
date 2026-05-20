//! Env-pack registry: binds a [`PackDescriptor`](greentic_deploy_spec::PackDescriptor)
//! `kind` to a native capability handler (`A9`).
//!
//! - [`slot`] — the [`EnvPackHandler`](slot::EnvPackHandler) trait and the
//!   built-in, metadata-only handlers for the five default `local` bindings.
//! - [`registry`] — [`EnvPackRegistry`](registry::EnvPackRegistry): built-in
//!   registrations plus the Phase D plug-in `register` hook.

pub mod registry;
pub mod slot;

pub use registry::{EnvPackRegistry, RegistryError};
pub use slot::{BUILTIN_HANDLERS, BuiltinHandler, EnvPackHandler};
