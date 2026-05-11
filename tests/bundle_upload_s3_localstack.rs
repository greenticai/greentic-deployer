// greentic-deployer/tests/bundle_upload_s3_localstack.rs
//!
//! Integration tests for `S3Uploader` against LocalStack.
//!
//! Skipped automatically unless `LOCALSTACK_ENDPOINT` env var is set, e.g.:
//!     LOCALSTACK_ENDPOINT=http://localhost:4566 cargo test --features bundle-upload-aws \
//!         --test bundle_upload_s3_localstack
//!
//! Run LocalStack locally with:
//!     docker run --rm -p 4566:4566 localstack/localstack:latest

#![cfg(feature = "bundle-upload-aws")]

use std::env;
use std::io::Write;

use greentic_deployer::bundle_upload::{BundleUploadError, UploadOptions, from_url};

fn localstack_endpoint() -> Option<String> {
    env::var("LOCALSTACK_ENDPOINT").ok()
}

fn fixture_bundle() -> tempfile::NamedTempFile {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(b"fake bundle bytes for tests").unwrap();
    tmp.flush().unwrap();
    tmp
}

#[tokio::test]
async fn happy_path_upload_and_presign() {
    let Some(endpoint) = localstack_endpoint() else {
        eprintln!("LOCALSTACK_ENDPOINT not set; skipping");
        return;
    };
    // Configure aws-config to point at LocalStack via standard env vars.
    unsafe {
        env::set_var("AWS_ACCESS_KEY_ID", "test");
        env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        env::set_var("AWS_REGION", "us-east-1");
        env::set_var("AWS_ENDPOINT_URL", &endpoint);
    }
    let bundle = fixture_bundle();
    let url = "s3://test-happy-path-bucket/bundles/";
    let uploader = from_url(url).expect("uploader for s3 url");
    let opts = UploadOptions::default();
    let result = uploader.upload(bundle.path(), &opts).await.expect("upload");
    assert!(result.url.starts_with("http"));
    assert!(result.digest.starts_with("sha256:"));
    assert!(result.expires_at.is_some());
    assert!(
        result
            .object_ref
            .starts_with("s3://test-happy-path-bucket/")
    );
}

#[tokio::test]
async fn idempotent_reupload_skips_putobject() {
    let Some(endpoint) = localstack_endpoint() else {
        eprintln!("LOCALSTACK_ENDPOINT not set; skipping");
        return;
    };
    unsafe {
        env::set_var("AWS_ACCESS_KEY_ID", "test");
        env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        env::set_var("AWS_REGION", "us-east-1");
        env::set_var("AWS_ENDPOINT_URL", &endpoint);
    }
    let bundle = fixture_bundle();
    let url = "s3://test-idempotent-bucket/bundles/";
    let uploader = from_url(url).expect("uploader");
    let opts = UploadOptions::default();
    let r1 = uploader
        .upload(bundle.path(), &opts)
        .await
        .expect("first upload");
    let r2 = uploader
        .upload(bundle.path(), &opts)
        .await
        .expect("second upload");
    assert_eq!(r1.digest, r2.digest);
    assert_eq!(r1.object_ref, r2.object_ref);
    // URLs may differ (re-presigned), but both must be valid and refer to same key.
    assert!(r2.url.contains(&r2.digest[7..23]));
}

#[tokio::test]
async fn refresh_url_reissues_without_reupload() {
    let Some(endpoint) = localstack_endpoint() else {
        eprintln!("LOCALSTACK_ENDPOINT not set; skipping");
        return;
    };
    unsafe {
        env::set_var("AWS_ACCESS_KEY_ID", "test");
        env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        env::set_var("AWS_REGION", "us-east-1");
        env::set_var("AWS_ENDPOINT_URL", &endpoint);
    }
    let bundle = fixture_bundle();
    let url = "s3://test-refresh-bucket/bundles/";
    let uploader = from_url(url).expect("uploader");
    let opts = UploadOptions::default();
    let initial = uploader.upload(bundle.path(), &opts).await.expect("upload");
    let refreshed = uploader
        .refresh_url(&initial.object_ref, &opts)
        .await
        .expect("refresh");
    assert_eq!(refreshed.object_ref, initial.object_ref);
    assert_eq!(refreshed.digest, initial.digest);
}

#[tokio::test]
async fn refresh_missing_object_returns_error() {
    let Some(endpoint) = localstack_endpoint() else {
        eprintln!("LOCALSTACK_ENDPOINT not set; skipping");
        return;
    };
    unsafe {
        env::set_var("AWS_ACCESS_KEY_ID", "test");
        env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        env::set_var("AWS_REGION", "us-east-1");
        env::set_var("AWS_ENDPOINT_URL", &endpoint);
    }
    let url = "s3://test-missing-bucket/bundles/";
    let uploader = from_url(url).expect("uploader");
    let opts = UploadOptions::default();
    let err = uploader
        .refresh_url(
            "s3://test-missing-bucket/bundles/does-not-exist.gtbundle",
            &opts,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, BundleUploadError::ObjectMissing(_)));
}
