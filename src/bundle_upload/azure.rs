//! Azure Blob implementation of `BundleUploader` (stub).
//!
//! Compiled only when the `bundle-upload-azure` cargo feature is enabled.

use std::path::Path;

use super::error::{BundleUploadError, BundleUploadResult};
use super::types::{UploadOptions, UploadedBundle};
use super::uploader::BundleUploader;

#[derive(Debug)]
pub struct AzureUploader;

impl AzureUploader {
    pub fn from_url(_url: &str) -> BundleUploadResult<Self> {
        Err(BundleUploadError::Other(
            "AzureUploader::from_url not yet implemented; populate this stub when first Azure demo lands"
                .to_string(),
        ))
    }
}

#[async_trait::async_trait]
impl BundleUploader for AzureUploader {
    async fn upload(
        &self,
        _bundle_path: &Path,
        _opts: &UploadOptions,
    ) -> BundleUploadResult<UploadedBundle> {
        unimplemented!("AzureUploader::upload not yet implemented")
    }

    async fn refresh_url(
        &self,
        _object_ref: &str,
        _opts: &UploadOptions,
    ) -> BundleUploadResult<UploadedBundle> {
        unimplemented!("AzureUploader::refresh_url not yet implemented")
    }
}
