use super::error::{BundleUploadError, BundleUploadResult};
use super::uploader::BundleUploader;

/// Resolve a `BundleUploader` impl from the URL scheme.
pub fn from_url(url: &str) -> BundleUploadResult<Box<dyn BundleUploader>> {
    let parsed =
        url::Url::parse(url).map_err(|_| BundleUploadError::InvalidUrl(url.to_string()))?;

    match parsed.scheme() {
        "s3" => from_s3_url(url),
        "gs" => from_gs_url(url),
        "https" if is_azure_blob_host(parsed.host_str().unwrap_or("")) => from_azure_url(url),
        other => Err(BundleUploadError::InvalidUrl(format!(
            "{other}://... (full url: {url})"
        ))),
    }
}

fn is_azure_blob_host(host: &str) -> bool {
    host.ends_with(".blob.core.windows.net")
}

#[cfg(feature = "bundle-upload-aws")]
fn from_s3_url(url: &str) -> BundleUploadResult<Box<dyn BundleUploader>> {
    Ok(Box::new(super::s3::S3Uploader::from_url(url)?))
}

#[cfg(not(feature = "bundle-upload-aws"))]
fn from_s3_url(_url: &str) -> BundleUploadResult<Box<dyn BundleUploader>> {
    Err(BundleUploadError::FeatureNotEnabled {
        scheme: "s3".to_string(),
        feature: "bundle-upload-aws".to_string(),
    })
}

#[cfg(feature = "bundle-upload-gcp")]
fn from_gs_url(_url: &str) -> BundleUploadResult<Box<dyn BundleUploader>> {
    Err(BundleUploadError::Other(
        "GCS uploader not yet implemented".to_string(),
    ))
}

#[cfg(not(feature = "bundle-upload-gcp"))]
fn from_gs_url(_url: &str) -> BundleUploadResult<Box<dyn BundleUploader>> {
    Err(BundleUploadError::FeatureNotEnabled {
        scheme: "gs".to_string(),
        feature: "bundle-upload-gcp".to_string(),
    })
}

#[cfg(feature = "bundle-upload-azure")]
fn from_azure_url(_url: &str) -> BundleUploadResult<Box<dyn BundleUploader>> {
    Err(BundleUploadError::Other(
        "Azure Blob uploader not yet implemented".to_string(),
    ))
}

#[cfg(not(feature = "bundle-upload-azure"))]
fn from_azure_url(_url: &str) -> BundleUploadResult<Box<dyn BundleUploader>> {
    Err(BundleUploadError::FeatureNotEnabled {
        scheme: "https (azure-blob)".to_string(),
        feature: "bundle-upload-azure".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_scheme() {
        let err = from_url("ftp://example.com/bundle").unwrap_err();
        assert!(matches!(err, BundleUploadError::InvalidUrl(_)));
    }

    #[test]
    fn rejects_garbage_input() {
        let err = from_url("not a url").unwrap_err();
        assert!(matches!(err, BundleUploadError::InvalidUrl(_)));
    }

    #[test]
    fn accepts_s3_url_with_aws_feature() {
        let result = from_url("s3://my-bucket/my-key/");
        #[cfg(feature = "bundle-upload-aws")]
        assert!(
            result.is_ok(),
            "expected Ok with aws feature: {:?}",
            result.err()
        );
        #[cfg(not(feature = "bundle-upload-aws"))]
        assert!(matches!(
            result.unwrap_err(),
            BundleUploadError::FeatureNotEnabled { .. }
        ));
    }

    #[test]
    fn rejects_gs_url_without_gcp_feature() {
        let err = from_url("gs://my-bucket/my-key/").unwrap_err();
        #[cfg(feature = "bundle-upload-gcp")]
        assert!(
            matches!(err, BundleUploadError::Other(_)),
            "expected not-yet-implemented error with gcp feature: {err:?}"
        );
        #[cfg(not(feature = "bundle-upload-gcp"))]
        assert!(matches!(err, BundleUploadError::FeatureNotEnabled { .. }));
    }

    #[test]
    fn rejects_https_non_azure_host() {
        let err = from_url("https://example.com/bundle").unwrap_err();
        assert!(matches!(err, BundleUploadError::InvalidUrl(_)));
    }

    #[test]
    fn azure_blob_host_detection() {
        assert!(is_azure_blob_host("foo.blob.core.windows.net"));
        assert!(is_azure_blob_host("bar.example.blob.core.windows.net"));
        assert!(!is_azure_blob_host("example.com"));
        assert!(!is_azure_blob_host("blob.core.windows.net.evil.com"));
    }
}
