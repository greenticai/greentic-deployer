//! Deploy extension runtime integration.
//!
//! Loaded with `--features extensions`. See
//! `docs/superpowers/specs/2026-04-17-deploy-extension-migration-design.md`.

pub mod describe;
pub mod errors;
pub mod loader;
pub mod registry;
pub mod wasm;
pub mod builtin_bridge;
pub mod dispatcher;
pub mod cli;

pub use errors::ExtensionError;
