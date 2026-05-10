// greentic-deployer/src/bundle_upload/s3.rs
//! S3 implementation of `BundleUploader`.
//!
//! Compiled only when the `bundle-upload-aws` cargo feature is enabled.

use std::path::{Path, PathBuf};

use super::error::{AWS_CREDENTIALS_REFRESH_HELP, BundleUploadError, BundleUploadResult};
use super::types::{UploadOptions, UploadedBundle};
use super::uploader::BundleUploader;

#[derive(Debug, Clone)]
pub struct S3Target {
    pub bucket: String,
    pub key_prefix: String,
}

impl S3Target {
    pub fn parse(url: &str) -> BundleUploadResult<Self> {
        let parsed =
            url::Url::parse(url).map_err(|_| BundleUploadError::InvalidUrl(url.to_string()))?;
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
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if !env_has_explicit_aws_access_key()
            && let Some(credentials) = load_shared_file_static_credentials()
        {
            loader = loader.credentials_provider(credentials);
        }
        let config = loader.load().await;
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
                    "AWS region not configured; set AWS_REGION or ~/.aws/config region".to_string(),
                )
            })
    }

    fn aws_operation_error(action: &str, detail: impl std::fmt::Debug) -> BundleUploadError {
        let detail = format!("{detail:?}");
        if is_aws_credentials_refresh_required(&detail) {
            BundleUploadError::AwsCredentialsRefreshRequired {
                action: action.to_string(),
                help: &AWS_CREDENTIALS_REFRESH_HELP,
            }
        } else {
            BundleUploadError::Other(format!("{action}: {detail}"))
        }
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
            Err(sdk_err) => {
                let status = sdk_err
                    .raw_response()
                    .map(|response| response.status().as_u16());
                let bucket_region = sdk_err
                    .raw_response()
                    .and_then(|response| response.headers().get("x-amz-bucket-region"))
                    .map(str::to_string);
                match sdk_err.into_service_error() {
                    HeadBucketError::NotFound(_) => true,
                    other => {
                        return Err(Self::head_bucket_error(
                            bucket,
                            status,
                            bucket_region.as_deref(),
                            Self::region_or_error(client).ok().as_deref(),
                            other,
                        ));
                    }
                }
            }
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
                    Self::aws_operation_error(&format!("creating S3 bucket {bucket}"), svc)
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
                Self::aws_operation_error(
                    "configuring S3 bucket public access block",
                    err.into_service_error(),
                )
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
                Self::aws_operation_error(
                    "configuring S3 bucket versioning",
                    err.into_service_error(),
                )
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
                                    .map_err(|e| {
                                        BundleUploadError::Other(format!("SSE config: {e}"))
                                    })?,
                            )
                            .build(),
                    )
                    .build()
                    .map_err(|e| BundleUploadError::Other(format!("encryption config: {e}")))?,
            )
            .send()
            .await
            .map_err(|err| {
                Self::aws_operation_error(
                    "configuring S3 bucket encryption",
                    err.into_service_error(),
                )
            })?;

        Ok(())
    }

    async fn presign_get(
        &self,
        client: &aws_sdk_s3::Client,
        key: &str,
        digest: &str,
        object_ref: &str,
        opts: &UploadOptions,
    ) -> BundleUploadResult<UploadedBundle> {
        use aws_sdk_s3::presigning::PresigningConfig;
        use std::time::Duration;

        let expires_secs = opts.clamped_for_s3();
        let presigning = PresigningConfig::expires_in(Duration::from_secs(expires_secs))
            .map_err(|e| BundleUploadError::Other(format!("presigning config: {e}")))?;
        let presigned = client
            .get_object()
            .bucket(&self.target.bucket)
            .key(key)
            .presigned(presigning)
            .await
            .map_err(|err| {
                Self::aws_operation_error(
                    "creating presigned S3 download URL",
                    err.into_service_error(),
                )
            })?;

        let url = presigned.uri().to_string();
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(expires_secs as i64);

        Ok(UploadedBundle {
            url,
            digest: digest.to_string(),
            expires_at: Some(expires_at),
            object_ref: object_ref.to_string(),
        })
    }

    fn head_bucket_error(
        bucket: &str,
        status: Option<u16>,
        bucket_region: Option<&str>,
        configured_region: Option<&str>,
        detail: impl std::fmt::Debug,
    ) -> BundleUploadError {
        match status {
            Some(301) | Some(400) if bucket_region.is_some() => {
                let bucket_region = bucket_region.unwrap();
                let configured_region = configured_region.unwrap_or("<not configured>");
                BundleUploadError::Other(format!(
                    "S3 bucket {bucket} is in region {bucket_region}, but the deployer is using region {configured_region}; set AWS_REGION={bucket_region} and retry"
                ))
            }
            Some(403) => BundleUploadError::AccessDenied {
                action: "checking S3 bucket".to_string(),
                resource: format!("s3://{bucket}"),
                required_perms: "s3:ListBucket on the bucket, or use a bucket owned by the configured AWS account".to_string(),
            },
            _ => Self::aws_operation_error(&format!("checking S3 bucket {bucket}"), detail),
        }
    }
}

#[async_trait::async_trait]
impl BundleUploader for S3Uploader {
    async fn upload(
        &self,
        bundle_path: &Path,
        opts: &UploadOptions,
    ) -> BundleUploadResult<UploadedBundle> {
        let client = self.s3_client().await?;
        self.ensure_bucket(&client).await?;

        let (full_digest, short_digest) = digest_file(bundle_path).await?;
        let key = self.target.compose_key(&format!("{short_digest}.gtbundle"));

        // Idempotency: HeadObject; skip PutObject if metadata matches.
        let head = client
            .head_object()
            .bucket(&self.target.bucket)
            .key(&key)
            .send()
            .await;

        let must_upload = match head {
            Ok(out) => {
                let existing = out
                    .metadata()
                    .and_then(|m| m.get("greentic-bundle-digest"))
                    .map(|s| s.as_str());
                existing != Some(full_digest.as_str())
            }
            Err(sdk_err) => match sdk_err.into_service_error() {
                aws_sdk_s3::operation::head_object::HeadObjectError::NotFound(_) => true,
                other => {
                    return Err(Self::aws_operation_error(
                        &format!("checking S3 object {key}"),
                        other,
                    ));
                }
            },
        };

        if must_upload {
            let body = aws_sdk_s3::primitives::ByteStream::from_path(bundle_path)
                .await
                .map_err(|e| BundleUploadError::Other(format!("read bundle: {e}")))?;
            client
                .put_object()
                .bucket(&self.target.bucket)
                .key(&key)
                .body(body)
                .metadata("greentic-bundle-digest", &full_digest)
                .content_type("application/octet-stream")
                .send()
                .await
                .map_err(|err| {
                    Self::aws_operation_error("uploading bundle to S3", err.into_service_error())
                })?;
        }

        let object_ref = format!("s3://{}/{}", self.target.bucket, key);
        let uploaded = self
            .presign_get(&client, &key, &full_digest, &object_ref, opts)
            .await?;
        Ok(uploaded)
    }

    async fn refresh_url(
        &self,
        object_ref: &str,
        opts: &UploadOptions,
    ) -> BundleUploadResult<UploadedBundle> {
        // Parse object_ref back into bucket + key.
        let parsed = url::Url::parse(object_ref)
            .map_err(|_| BundleUploadError::InvalidUrl(object_ref.to_string()))?;
        if parsed.scheme() != "s3" {
            return Err(BundleUploadError::InvalidUrl(object_ref.to_string()));
        }
        let bucket = parsed
            .host_str()
            .ok_or_else(|| BundleUploadError::InvalidUrl(object_ref.to_string()))?;
        let key = parsed.path().trim_start_matches('/');
        if bucket != self.target.bucket {
            return Err(BundleUploadError::Other(format!(
                "object_ref bucket {bucket} does not match uploader bucket {}",
                self.target.bucket
            )));
        }

        let client = self.s3_client().await?;
        // Confirm object exists + extract digest from metadata.
        let head = client
            .head_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|err| {
                let svc = err.into_service_error();
                if let aws_sdk_s3::operation::head_object::HeadObjectError::NotFound(_) = svc {
                    BundleUploadError::ObjectMissing(object_ref.to_string())
                } else {
                    Self::aws_operation_error(&format!("checking S3 object {key}"), svc)
                }
            })?;
        let digest = head
            .metadata()
            .and_then(|m| m.get("greentic-bundle-digest"))
            .cloned()
            .unwrap_or_else(|| "sha256:unknown".to_string());

        self.presign_get(&client, key, &digest, object_ref, opts)
            .await
    }
}

fn is_aws_credentials_refresh_required(detail: &str) -> bool {
    detail.contains("TokenExpired")
        || detail.contains("ExpiredToken")
        || detail.contains("The refresh token has expired")
        || detail.contains("Your session has expired")
        || detail.contains("security token included in the request is expired")
}

fn env_has_explicit_aws_access_key() -> bool {
    std::env::var_os("AWS_ACCESS_KEY_ID").is_some()
}

fn load_shared_file_static_credentials() -> Option<aws_sdk_s3::config::Credentials> {
    let profile = selected_aws_profile();
    let path = shared_credentials_path()?;
    let contents = std::fs::read_to_string(path).ok()?;
    let credentials = parse_shared_credentials_profile(&contents, &profile)?;
    Some(aws_sdk_s3::config::Credentials::new(
        credentials.access_key_id,
        credentials.secret_access_key,
        credentials.session_token,
        None,
        "shared-credentials-file",
    ))
}

fn selected_aws_profile() -> String {
    std::env::var("AWS_PROFILE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("AWS_DEFAULT_PROFILE")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or_else(|| "default".to_string())
}

fn shared_credentials_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("AWS_SHARED_CREDENTIALS_FILE")
        && !path.is_empty()
    {
        return Some(PathBuf::from(path));
    }
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .filter(|home| !home.is_empty())
                .map(PathBuf::from)
        })
        .map(|home| home.join(".aws").join("credentials"))
}

#[derive(Debug, PartialEq, Eq)]
struct SharedFileCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

fn parse_shared_credentials_profile(
    contents: &str,
    profile: &str,
) -> Option<SharedFileCredentials> {
    let mut in_selected_profile = false;
    let mut access_key_id = None;
    let mut secret_access_key = None;
    let mut session_token = None;

    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(section) = line
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
        {
            let section = section
                .trim()
                .strip_prefix("profile ")
                .unwrap_or_else(|| section.trim())
                .trim();
            in_selected_profile = section == profile;
            continue;
        }
        if !in_selected_profile {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"').to_string();
        match key {
            "aws_access_key_id" if !value.is_empty() => access_key_id = Some(value),
            "aws_secret_access_key" if !value.is_empty() => secret_access_key = Some(value),
            "aws_session_token" if !value.is_empty() => session_token = Some(value),
            _ => {}
        }
    }

    Some(SharedFileCredentials {
        access_key_id: access_key_id?,
        secret_access_key: secret_access_key?,
        session_token,
    })
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

    #[test]
    fn expired_aws_credentials_map_to_actionable_error() {
        let err = S3Uploader::aws_operation_error(
            "checking S3 bucket demo",
            "ProviderError RefreshFailed AccessDeniedException TokenExpired The refresh token has expired",
        );
        match err {
            BundleUploadError::AwsCredentialsRefreshRequired { action, help } => {
                assert_eq!(action, "checking S3 bucket demo");
                assert_eq!(help.configure_command, "aws configure");
                assert_eq!(
                    help.session_token_check_command,
                    "aws configure get aws_session_token"
                );
                assert_eq!(
                    help.session_token_unset_command,
                    "unset AWS_SESSION_TOKEN AWS_SECURITY_TOKEN"
                );
                assert_eq!(help.sso_login_command, "aws sso login");
                assert_eq!(help.profile_env_command, "export AWS_PROFILE=<profile>");
                assert_eq!(
                    help.profile_configure_command,
                    "aws configure --profile <profile>"
                );
                assert_eq!(
                    help.profile_sso_login_command,
                    "aws sso login --profile <profile>"
                );
                assert_eq!(help.verify_command, "aws sts get-caller-identity");
                let rendered =
                    BundleUploadError::AwsCredentialsRefreshRequired { action, help }.to_string();
                assert!(rendered.contains("AWS credentials need to be refreshed"));
                assert!(rendered.contains("aws configure"));
                assert!(rendered.contains("aws configure get aws_session_token"));
                assert!(rendered.contains("unset AWS_SESSION_TOKEN AWS_SECURITY_TOKEN"));
                assert!(rendered.contains("aws sso login"));
                assert!(rendered.contains("aws sts get-caller-identity"));
            }
            other => panic!("expected credentials refresh error, got {other:?}"),
        }
    }

    #[test]
    fn bundle_upload_errors_expose_message_keys() {
        let err = S3Uploader::aws_operation_error(
            "checking S3 bucket demo",
            "Your session has expired. Please reauthenticate.",
        );
        assert_eq!(
            err.message_key(),
            "bundle_upload.aws.credentials_refresh_required"
        );
    }

    #[test]
    fn generic_refresh_failure_stays_unclassified() {
        let err = S3Uploader::aws_operation_error(
            "checking S3 bucket demo",
            "ProviderError RefreshFailed without expiration details",
        );
        assert!(matches!(err, BundleUploadError::Other(_)));
    }

    #[test]
    fn head_bucket_forbidden_maps_to_access_denied() {
        let err =
            S3Uploader::head_bucket_error("demo", Some(403), None, Some("eu-north-1"), "no body");
        match err {
            BundleUploadError::AccessDenied {
                action,
                resource,
                required_perms,
            } => {
                assert_eq!(action, "checking S3 bucket");
                assert_eq!(resource, "s3://demo");
                assert!(required_perms.contains("s3:ListBucket"));
            }
            other => panic!("expected access denied, got {other:?}"),
        }
    }

    #[test]
    fn head_bucket_region_mismatch_includes_bucket_region() {
        let err = S3Uploader::head_bucket_error(
            "demo",
            Some(301),
            Some("us-east-1"),
            Some("eu-north-1"),
            "no body",
        );
        let rendered = err.to_string();
        assert!(rendered.contains("us-east-1"));
        assert!(rendered.contains("eu-north-1"));
        assert!(rendered.contains("AWS_REGION=us-east-1"));
    }

    #[test]
    fn parses_default_shared_file_static_credentials() {
        let credentials = parse_shared_credentials_profile(
            r#"
[default]
aws_access_key_id = AKIADEFAULT
aws_secret_access_key = default-secret

[prod]
aws_access_key_id = AKIAPROD
aws_secret_access_key = prod-secret
"#,
            "default",
        )
        .unwrap();
        assert_eq!(
            credentials,
            SharedFileCredentials {
                access_key_id: "AKIADEFAULT".to_string(),
                secret_access_key: "default-secret".to_string(),
                session_token: None,
            }
        );
    }

    #[test]
    fn parses_named_shared_file_static_credentials_with_session_token() {
        let credentials = parse_shared_credentials_profile(
            r#"
[profile dev]
aws_access_key_id = AKIADEV
aws_secret_access_key = dev-secret
aws_session_token = dev-token
"#,
            "dev",
        )
        .unwrap();
        assert_eq!(
            credentials,
            SharedFileCredentials {
                access_key_id: "AKIADEV".to_string(),
                secret_access_key: "dev-secret".to_string(),
                session_token: Some("dev-token".to_string()),
            }
        );
    }

    #[test]
    fn ignores_incomplete_shared_file_credentials() {
        assert!(
            parse_shared_credentials_profile("[default]\naws_access_key_id = AKIA\n", "default")
                .is_none()
        );
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
