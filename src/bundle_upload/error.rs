use thiserror::Error;

#[derive(Debug, Error)]
pub enum BundleUploadError {
    #[error("unsupported upload scheme '{0}'; expected one of: s3://, gs://, https://*.blob.core.windows.net/")]
    InvalidUrl(String),

    #[error("scheme '{scheme}' requires building greentic-deployer with --features {feature}")]
    FeatureNotEnabled { scheme: String, feature: String },

    #[error("bucket '{0}' is taken in the global S3 namespace; pick another name (S3 bucket names are globally unique)")]
    BucketAlreadyExistsInOtherAccount(String),

    #[error("access denied for {action} on {resource}: required IAM permissions: {required_perms}")]
    AccessDenied {
        action: String,
        resource: String,
        required_perms: String,
    },

    #[error("object '{0}' not found; run upload-bundle again to recreate")]
    ObjectMissing(String),

    #[error("greentic-start warmup failed (exit {exit_code}):\n{stderr}")]
    WarmupFailed { exit_code: i32, stderr: String },

    #[error("network error after retries: {0}")]
    NetworkTransient(String),

    #[error("AWS credentials could not be resolved; configure with `aws configure` or set AWS_PROFILE / AWS_ACCESS_KEY_ID env vars")]
    CredentialsUnresolved,

    #[error("digest mismatch: expected {expected}, computed {actual}")]
    DigestMismatch { expected: String, actual: String },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type BundleUploadResult<T> = std::result::Result<T, BundleUploadError>;
