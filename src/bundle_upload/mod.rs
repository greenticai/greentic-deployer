//! Cloud bundle upload abstraction.
//!
//! See `docs/superpowers/specs/2026-05-07-gtc-bundle-upload-flag-design.md`.

mod dispatcher;
mod error;
mod types;
mod uploader;

#[cfg(feature = "bundle-upload-aws")]
pub mod s3;

#[cfg(feature = "bundle-upload-gcp")]
pub mod gcs;

#[cfg(feature = "bundle-upload-azure")]
pub mod azure;

pub use dispatcher::from_url;
pub use error::{BundleUploadError, BundleUploadResult};
pub use types::{UploadOptions, UploadedBundle};
pub use uploader::BundleUploader;
