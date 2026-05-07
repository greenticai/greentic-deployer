use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadedBundle {
    pub url: String,
    pub digest: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub object_ref: String,
}

#[derive(Debug, Clone)]
pub struct UploadOptions {
    pub presign_expires_secs: u64,
}

impl Default for UploadOptions {
    fn default() -> Self {
        Self {
            presign_expires_secs: 604800,
        }
    }
}

impl UploadOptions {
    /// S3 SigV4 hard limit on presigned URL expiry.
    pub const S3_MAX_PRESIGN_EXPIRES_SECS: u64 = 604800;

    /// Clamp expiry to S3 maximum.
    pub fn clamped_for_s3(&self) -> u64 {
        self.presign_expires_secs.min(Self::S3_MAX_PRESIGN_EXPIRES_SECS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_expiry_is_seven_days() {
        let opts = UploadOptions::default();
        assert_eq!(opts.presign_expires_secs, 604800);
    }

    #[test]
    fn s3_clamp_caps_at_seven_days() {
        let opts = UploadOptions {
            presign_expires_secs: 9_999_999,
        };
        assert_eq!(opts.clamped_for_s3(), 604800);
    }

    #[test]
    fn s3_clamp_passes_smaller_values_through() {
        let opts = UploadOptions {
            presign_expires_secs: 3600,
        };
        assert_eq!(opts.clamped_for_s3(), 3600);
    }

    #[test]
    fn uploaded_bundle_serializes_to_json() {
        let bundle = UploadedBundle {
            url: "https://example.com/bundle".to_string(),
            digest: "sha256:abc".to_string(),
            expires_at: None,
            object_ref: "s3://bucket/key".to_string(),
        };
        let json = serde_json::to_string(&bundle).unwrap();
        assert!(json.contains("\"url\":\"https://example.com/bundle\""));
        assert!(json.contains("\"digest\":\"sha256:abc\""));
    }
}
