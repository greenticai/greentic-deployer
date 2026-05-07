use std::path::Path;

use super::error::BundleUploadResult;
use super::types::{UploadOptions, UploadedBundle};

/// Cloud-agnostic interface for uploading a `.gtbundle` and producing a fetchable URL.
///
/// Implementors:
/// - `S3Uploader` (feature `bundle-upload-aws`)
/// - `GcsUploader` (feature `bundle-upload-gcp`, currently stub)
/// - `AzureUploader` (feature `bundle-upload-azure`, currently stub)
#[async_trait::async_trait]
pub trait BundleUploader: Send + Sync {
    /// Upload `bundle_path`. If an object with matching digest already exists at
    /// the target key, skip the byte upload and proceed to URL issuance.
    async fn upload(
        &self,
        bundle_path: &Path,
        opts: &UploadOptions,
    ) -> BundleUploadResult<UploadedBundle>;

    /// Re-issue a fresh URL for an existing uploaded bundle without re-uploading.
    /// `object_ref` is the value previously returned in `UploadedBundle::object_ref`.
    async fn refresh_url(
        &self,
        object_ref: &str,
        opts: &UploadOptions,
    ) -> BundleUploadResult<UploadedBundle>;
}
