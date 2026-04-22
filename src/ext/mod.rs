//! Deploy extension runtime integration.
//!
//! Loaded with `--features extensions`. See
//! `docs/superpowers/specs/2026-04-17-deploy-extension-migration-design.md`.

pub mod backend_adapter;
pub mod builtin_bridge;
pub mod cli;
pub mod describe;
pub mod diagnostic;
pub mod dispatcher;
pub mod errors;
pub mod loader;
pub mod registry;
pub mod wasm;

pub use errors::ExtensionError;
pub use registry::ExtensionRegistry;
