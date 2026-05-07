//! GCS implementation of `BundleUploader` (stub).
//!
//! Compiled only when the `bundle-upload-gcp` cargo feature is enabled.
//! Currently returns `unimplemented!()` for all operations; populated when
//! the first GCP demo deploy is needed.

use std::path::Path;

use super::error::{BundleUploadError, BundleUploadResult};
use super::types::{UploadOptions, UploadedBundle};
use super::uploader::BundleUploader;

#[derive(Debug)]
pub struct GcsUploader;

impl GcsUploader {
    pub fn from_url(_url: &str) -> BundleUploadResult<Self> {
        Err(BundleUploadError::Other(
            "GcsUploader::from_url not yet implemented; populate this stub when first GCP demo lands"
                .to_string(),
        ))
    }
}

#[async_trait::async_trait]
impl BundleUploader for GcsUploader {
    async fn upload(
        &self,
        _bundle_path: &Path,
        _opts: &UploadOptions,
    ) -> BundleUploadResult<UploadedBundle> {
        unimplemented!("GcsUploader::upload not yet implemented")
    }

    async fn refresh_url(
        &self,
        _object_ref: &str,
        _opts: &UploadOptions,
    ) -> BundleUploadResult<UploadedBundle> {
        unimplemented!("GcsUploader::refresh_url not yet implemented")
    }
}
