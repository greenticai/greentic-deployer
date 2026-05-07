// greentic-deployer/src/bundle_upload/s3.rs
//! S3 implementation of `BundleUploader`.
//!
//! Compiled only when the `bundle-upload-aws` cargo feature is enabled.

use std::path::Path;

use super::error::{BundleUploadError, BundleUploadResult};
use super::types::{UploadOptions, UploadedBundle};
use super::uploader::BundleUploader;

#[derive(Debug, Clone)]
pub struct S3Target {
    pub bucket: String,
    pub key_prefix: String,
}

impl S3Target {
    pub fn parse(url: &str) -> BundleUploadResult<Self> {
        let parsed = url::Url::parse(url)
            .map_err(|_| BundleUploadError::InvalidUrl(url.to_string()))?;
        if parsed.scheme() != "s3" {
            return Err(BundleUploadError::InvalidUrl(url.to_string()));
        }
        let bucket = parsed
            .host_str()
            .ok_or_else(|| BundleUploadError::InvalidUrl(url.to_string()))?
            .to_string();
        if bucket.is_empty() {
            return Err(BundleUploadError::InvalidUrl(url.to_string()));
        }
        // Strip leading slash; keep trailing slash semantics intact.
        let key_prefix = parsed.path().trim_start_matches('/').to_string();
        Ok(Self { bucket, key_prefix })
    }

    /// Compose an S3 key by joining `key_prefix` with a deterministic filename.
    pub fn compose_key(&self, filename: &str) -> String {
        if self.key_prefix.is_empty() {
            filename.to_string()
        } else if self.key_prefix.ends_with('/') {
            format!("{}{}", self.key_prefix, filename)
        } else {
            format!("{}/{}", self.key_prefix, filename)
        }
    }
}

#[derive(Debug)]
pub struct S3Uploader {
    target: S3Target,
}

impl S3Uploader {
    pub fn from_url(url: &str) -> BundleUploadResult<Self> {
        Ok(Self {
            target: S3Target::parse(url)?,
        })
    }

    async fn s3_client(&self) -> BundleUploadResult<aws_sdk_s3::Client> {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;
        if config.credentials_provider().is_none() {
            return Err(BundleUploadError::CredentialsUnresolved);
        }
        Ok(aws_sdk_s3::Client::new(&config))
    }

    fn region_or_error(client: &aws_sdk_s3::Client) -> BundleUploadResult<String> {
        client
            .config()
            .region()
            .map(|r| r.to_string())
            .ok_or_else(|| {
                BundleUploadError::Other(
                    "AWS region not configured; set AWS_REGION or ~/.aws/config region"
                        .to_string(),
                )
            })
    }

    /// Ensure bucket exists with private + versioned + SSE-S3 defaults.
    /// Idempotent: re-applies versioning + encryption + BPA on every call.
    async fn ensure_bucket(&self, client: &aws_sdk_s3::Client) -> BundleUploadResult<()> {
        use aws_sdk_s3::operation::head_bucket::HeadBucketError;
        use aws_sdk_s3::types::*;

        let bucket = &self.target.bucket;
        let head = client.head_bucket().bucket(bucket).send().await;
        let must_create = match head {
            Ok(_) => false,
            Err(sdk_err) => match sdk_err.into_service_error() {
                HeadBucketError::NotFound(_) => true,
                other => {
                    return Err(BundleUploadError::Other(format!(
                        "head_bucket {bucket}: {other:?}"
                    )));
                }
            },
        };

        if must_create {
            let region = Self::region_or_error(client)?;
            let mut create = client.create_bucket().bucket(bucket);
            // us-east-1 is the AWS default and must NOT have a LocationConstraint.
            if region != "us-east-1" {
                let constraint = BucketLocationConstraint::from(region.as_str());
                let cfg = CreateBucketConfiguration::builder()
                    .location_constraint(constraint)
                    .build();
                create = create.create_bucket_configuration(cfg);
            }
            create.send().await.map_err(|err| {
                let svc = err.into_service_error();
                if let aws_sdk_s3::operation::create_bucket::CreateBucketError::BucketAlreadyExists(_) = svc {
                    BundleUploadError::BucketAlreadyExistsInOtherAccount(bucket.clone())
                } else {
                    BundleUploadError::Other(format!("create_bucket {bucket}: {svc:?}"))
                }
            })?;
        }

        // Block all public access (idempotent).
        client
            .put_public_access_block()
            .bucket(bucket)
            .public_access_block_configuration(
                PublicAccessBlockConfiguration::builder()
                    .block_public_acls(true)
                    .ignore_public_acls(true)
                    .block_public_policy(true)
                    .restrict_public_buckets(true)
                    .build(),
            )
            .send()
            .await
            .map_err(|err| {
                BundleUploadError::Other(format!("put_public_access_block: {:?}", err.into_service_error()))
            })?;

        // Enable versioning (idempotent).
        client
            .put_bucket_versioning()
            .bucket(bucket)
            .versioning_configuration(
                VersioningConfiguration::builder()
                    .status(BucketVersioningStatus::Enabled)
                    .build(),
            )
            .send()
            .await
            .map_err(|err| {
                BundleUploadError::Other(format!("put_bucket_versioning: {:?}", err.into_service_error()))
            })?;

        // Enable SSE-S3 default encryption (idempotent).
        client
            .put_bucket_encryption()
            .bucket(bucket)
            .server_side_encryption_configuration(
                ServerSideEncryptionConfiguration::builder()
                    .rules(
                        ServerSideEncryptionRule::builder()
                            .apply_server_side_encryption_by_default(
                                ServerSideEncryptionByDefault::builder()
                                    .sse_algorithm(ServerSideEncryption::Aes256)
                                    .build()
                                    .map_err(|e| BundleUploadError::Other(format!("SSE config: {e}")))?,
                            )
                            .build(),
                    )
                    .build()
                    .map_err(|e| BundleUploadError::Other(format!("encryption config: {e}")))?,
            )
            .send()
            .await
            .map_err(|err| {
                BundleUploadError::Other(format!("put_bucket_encryption: {:?}", err.into_service_error()))
            })?;

        Ok(())
    }
}

#[async_trait::async_trait]
impl BundleUploader for S3Uploader {
    async fn upload(
        &self,
        _bundle_path: &Path,
        _opts: &UploadOptions,
    ) -> BundleUploadResult<UploadedBundle> {
        // Filled in by subsequent tasks.
        Err(BundleUploadError::Other(
            "S3Uploader::upload not yet implemented".to_string(),
        ))
    }

    async fn refresh_url(
        &self,
        _object_ref: &str,
        _opts: &UploadOptions,
    ) -> BundleUploadResult<UploadedBundle> {
        Err(BundleUploadError::Other(
            "S3Uploader::refresh_url not yet implemented".to_string(),
        ))
    }
}

/// Compute SHA256 of a file using streaming reads (handles arbitrarily large bundles).
/// Returns `("sha256:<full_hex>", "<short_hex_16>")`.
pub(crate) async fn digest_file(path: &Path) -> BundleUploadResult<(String, String)> {
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncReadExt;

    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let full_hex = hex::encode(hasher.finalize());
    let short_hex = full_hex[..16].to_string();
    Ok((format!("sha256:{full_hex}"), short_hex))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bucket_and_empty_prefix() {
        let target = S3Target::parse("s3://my-bucket/").unwrap();
        assert_eq!(target.bucket, "my-bucket");
        assert_eq!(target.key_prefix, "");
    }

    #[test]
    fn parses_bucket_and_simple_prefix() {
        let target = S3Target::parse("s3://my-bucket/bundles/").unwrap();
        assert_eq!(target.bucket, "my-bucket");
        assert_eq!(target.key_prefix, "bundles/");
    }

    #[test]
    fn parses_bucket_and_nested_prefix_no_trailing_slash() {
        let target = S3Target::parse("s3://my-bucket/path/to/bundles").unwrap();
        assert_eq!(target.bucket, "my-bucket");
        assert_eq!(target.key_prefix, "path/to/bundles");
    }

    #[test]
    fn rejects_non_s3_scheme() {
        assert!(S3Target::parse("https://my-bucket/").is_err());
    }

    #[test]
    fn rejects_empty_bucket() {
        // s3:/// has no host
        assert!(S3Target::parse("s3:///key").is_err());
    }

    #[test]
    fn compose_key_with_trailing_slash_prefix() {
        let target = S3Target {
            bucket: "b".into(),
            key_prefix: "bundles/".into(),
        };
        assert_eq!(target.compose_key("abc.gtbundle"), "bundles/abc.gtbundle");
    }

    #[test]
    fn compose_key_without_trailing_slash_prefix() {
        let target = S3Target {
            bucket: "b".into(),
            key_prefix: "bundles".into(),
        };
        assert_eq!(target.compose_key("abc.gtbundle"), "bundles/abc.gtbundle");
    }

    #[test]
    fn compose_key_empty_prefix() {
        let target = S3Target {
            bucket: "b".into(),
            key_prefix: "".into(),
        };
        assert_eq!(target.compose_key("abc.gtbundle"), "abc.gtbundle");
    }

    #[tokio::test]
    async fn digest_known_fixture() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"hello world").unwrap();
        tmp.flush().unwrap();
        let (full, short) = digest_file(tmp.path()).await.unwrap();
        // SHA256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
        assert_eq!(
            full,
            "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        assert_eq!(short, "b94d27b9934d3e08");
    }
}
