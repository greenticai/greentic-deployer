use thiserror::Error;

#[derive(Debug)]
pub struct AwsCredentialsRefreshHelp {
    pub configure_command: &'static str,
    pub session_token_check_command: &'static str,
    pub session_token_unset_command: &'static str,
    pub sso_login_command: &'static str,
    pub profile_env_command: &'static str,
    pub profile_configure_command: &'static str,
    pub profile_sso_login_command: &'static str,
    pub verify_command: &'static str,
}

impl std::fmt::Display for AwsCredentialsRefreshHelp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "If you use access keys, configure or refresh them:\n  {}\n\nIf access keys are configured but AWS still reports an expired token, check for a stale session token:\n  {}\n  {}\n\nIf you use AWS SSO, reauthenticate:\n  {}\n\nIf you use a named profile:\n  {}\n  {}\n  {}\n\nVerify the same credentials with:\n  {}",
            self.configure_command,
            self.session_token_check_command,
            self.session_token_unset_command,
            self.sso_login_command,
            self.profile_env_command,
            self.profile_configure_command,
            self.profile_sso_login_command,
            self.verify_command
        )
    }
}

pub static AWS_CREDENTIALS_REFRESH_HELP: AwsCredentialsRefreshHelp = AwsCredentialsRefreshHelp {
    configure_command: "aws configure",
    session_token_check_command: "aws configure get aws_session_token",
    session_token_unset_command: "unset AWS_SESSION_TOKEN AWS_SECURITY_TOKEN",
    sso_login_command: "aws sso login",
    profile_env_command: "export AWS_PROFILE=<profile>",
    profile_configure_command: "aws configure --profile <profile>",
    profile_sso_login_command: "aws sso login --profile <profile>",
    verify_command: "aws sts get-caller-identity",
};

#[derive(Debug, Error)]
pub enum BundleUploadError {
    #[error(
        "unsupported upload scheme '{0}'; expected one of: s3://, gs://, https://*.blob.core.windows.net/"
    )]
    InvalidUrl(String),

    #[error("scheme '{scheme}' requires building greentic-deployer with --features {feature}")]
    FeatureNotEnabled { scheme: String, feature: String },

    #[error(
        "bucket '{0}' is taken in the global S3 namespace; pick another name (S3 bucket names are globally unique)"
    )]
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

    #[error(
        "AWS credentials could not be resolved; configure with `aws configure` or set AWS_PROFILE / AWS_ACCESS_KEY_ID env vars"
    )]
    CredentialsUnresolved,

    #[error("AWS credentials need to be refreshed while {action}.\n\n{help}")]
    AwsCredentialsRefreshRequired {
        action: String,
        help: &'static AwsCredentialsRefreshHelp,
    },

    #[error("digest mismatch: expected {expected}, computed {actual}")]
    DigestMismatch { expected: String, actual: String },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

impl BundleUploadError {
    pub fn message_key(&self) -> &'static str {
        match self {
            Self::InvalidUrl(_) => "bundle_upload.invalid_url",
            Self::FeatureNotEnabled { .. } => "bundle_upload.feature_not_enabled",
            Self::BucketAlreadyExistsInOtherAccount(_) => {
                "bundle_upload.s3.bucket_already_exists_in_other_account"
            }
            Self::AccessDenied { .. } => "bundle_upload.access_denied",
            Self::ObjectMissing(_) => "bundle_upload.object_missing",
            Self::WarmupFailed { .. } => "bundle_upload.warmup_failed",
            Self::NetworkTransient(_) => "bundle_upload.network_transient",
            Self::CredentialsUnresolved => "bundle_upload.aws.credentials_unresolved",
            Self::AwsCredentialsRefreshRequired { .. } => {
                "bundle_upload.aws.credentials_refresh_required"
            }
            Self::DigestMismatch { .. } => "bundle_upload.digest_mismatch",
            Self::Io(_) => "bundle_upload.io",
            Self::Other(_) => "bundle_upload.other",
        }
    }
}

pub type BundleUploadResult<T> = std::result::Result<T, BundleUploadError>;
