# gtc Bundle Upload Flag — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the `gtc start --upload-bundle s3://...` one-command AWS deploy flow plus the companion `gtc deploy refresh-bundle-url` subcommand, as specified in `docs/superpowers/specs/2026-05-07-gtc-bundle-upload-flag-design.md`.

**Architecture:** A `BundleUploader` trait in `greentic-deployer/src/bundle_upload/` with an `S3Uploader` impl. Exposed to external callers via a new `greentic-deployer bundle-upload {upload,refresh-url}` subprocess CLI, which `gtc` invokes the same way it already invokes `greentic-deployer aws ...` and `terraform`. Cargo feature flags (`bundle-upload-aws`, `bundle-upload-gcp`, `bundle-upload-azure`) gate cloud-specific SDK dependencies; AWS is on by default.

**Tech Stack:** Rust 1.95 / edition 2024, `aws-sdk-s3`, `aws-config`, `async-trait`, `sha2`, `chrono`, `tokio`, `thiserror`. Spans two repos: `greentic-deployer` (trait, S3 impl, CLI subcommands, tests) and `greentic` (gtc flag wiring, refresh subcommand).

**Repos:**
- `greentic-deployer/` — primary. Branch: `feat/gtc-bundle-upload-flag` (already created with spec commit).
- `greentic/` — secondary. Branch to create: `feat/gtc-upload-bundle-flag`. Both target `main`.

---

## Phase 0: Setup

### Task 0.1: Pull greentic CLI repo and create branch

**Files:**
- Modify: `greentic/` working tree

- [ ] **Step 1: Pull main**

```bash
cd /home/bima-pangestu/Works/greentic/greentic
git fetch origin --quiet
git checkout main
git pull origin main
```

Expected: clean fast-forward.

- [ ] **Step 2: Create feature branch**

```bash
git checkout -b feat/gtc-upload-bundle-flag
```

Expected: `Switched to a new branch 'feat/gtc-upload-bundle-flag'`.

- [ ] **Step 3: Verify deployer branch is current**

```bash
cd /home/bima-pangestu/Works/greentic/greentic-deployer
git branch --show-current
```

Expected: `feat/gtc-bundle-upload-flag`.

---

## Phase 1: Deployer foundation (sequential — blocks everything else)

### Task 1.1: Add cargo features and dependencies in `greentic-deployer`

**Files:**
- Modify: `greentic-deployer/Cargo.toml`

- [ ] **Step 1: Add features and optional dependencies**

Replace the `[features]` block (currently lines 15–18):

```toml
[features]
default = ["bundle-upload-aws"]
internal-tools = []
test-utils = []
bundle-upload-aws = ["dep:aws-sdk-s3", "dep:aws-config", "dep:aws-smithy-runtime-api"]
bundle-upload-gcp = []
bundle-upload-azure = []
```

In `[dependencies]`, add:

```toml
aws-sdk-s3 = { version = "1", optional = true, default-features = false, features = ["rustls", "rt-tokio"] }
aws-config = { version = "1", optional = true, default-features = false, features = ["rustls", "rt-tokio"] }
aws-smithy-runtime-api = { version = "1", optional = true }
sha2 = "0.10"
hex = "0.4"
chrono = { version = "0.4", default-features = false, features = ["serde", "clock"] }
url = "2"
```

Remove existing `tokio` line and replace with:

```toml
tokio = { version = "1", features = ["rt-multi-thread", "macros", "fs", "io-util"] }
```

(adds `fs` + `io-util` for streaming digest computation).

- [ ] **Step 2: Verify build with default features**

```bash
cd /home/bima-pangestu/Works/greentic/greentic-deployer
cargo check --all-targets
```

Expected: clean build, AWS SDK deps fetched.

- [ ] **Step 3: Verify build without aws feature**

```bash
cargo check --all-targets --no-default-features
```

Expected: clean build, `aws-sdk-s3` not in dependency tree (verify with `cargo tree --no-default-features | grep aws-sdk-s3` returning no output).

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "build: add bundle-upload-aws cargo feature with aws-sdk-s3 deps"
```

---

### Task 1.2: Create `BundleUploadError` enum

**Files:**
- Create: `greentic-deployer/src/bundle_upload/error.rs`

- [ ] **Step 1: Create the file**

```rust
// greentic-deployer/src/bundle_upload/error.rs
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
```

- [ ] **Step 2: Compile-check**

```bash
cargo check
```

Expected: error "file not yet wired into module tree" — that's fine, will fix in Task 1.6.

- [ ] **Step 3: Commit**

```bash
git add src/bundle_upload/error.rs
git commit -m "feat(bundle-upload): add BundleUploadError enum"
```

---

### Task 1.3: Create `UploadedBundle` and `UploadOptions` types

**Files:**
- Create: `greentic-deployer/src/bundle_upload/types.rs`

- [ ] **Step 1: Write failing test**

Create `greentic-deployer/src/bundle_upload/types.rs`:

```rust
// greentic-deployer/src/bundle_upload/types.rs
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
```

- [ ] **Step 2: Verify test compiles (will fail to wire until Task 1.6)**

```bash
cargo build
```

Expected: build succeeds for the file in isolation; module not yet exposed via `lib.rs`.

- [ ] **Step 3: Commit**

```bash
git add src/bundle_upload/types.rs
git commit -m "feat(bundle-upload): add UploadedBundle + UploadOptions types"
```

---

### Task 1.4: Create `BundleUploader` trait

**Files:**
- Create: `greentic-deployer/src/bundle_upload/uploader.rs`

- [ ] **Step 1: Write the trait**

```rust
// greentic-deployer/src/bundle_upload/uploader.rs
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
```

- [ ] **Step 2: Commit**

```bash
git add src/bundle_upload/uploader.rs
git commit -m "feat(bundle-upload): add BundleUploader trait"
```

---

### Task 1.5: Create `from_url` dispatcher

**Files:**
- Create: `greentic-deployer/src/bundle_upload/dispatcher.rs`
- Test: included inline

- [ ] **Step 1: Write failing tests + dispatcher**

```rust
// greentic-deployer/src/bundle_upload/dispatcher.rs
use super::error::{BundleUploadError, BundleUploadResult};
use super::uploader::BundleUploader;

/// Resolve a `BundleUploader` impl from the URL scheme.
pub fn from_url(url: &str) -> BundleUploadResult<Box<dyn BundleUploader>> {
    let parsed = url::Url::parse(url)
        .map_err(|_| BundleUploadError::InvalidUrl(url.to_string()))?;

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
        // Default features include bundle-upload-aws, so this should succeed in
        // returning a Box<dyn BundleUploader>; we don't test the impl here.
        let result = from_url("s3://my-bucket/my-key/");
        #[cfg(feature = "bundle-upload-aws")]
        assert!(result.is_ok(), "expected Ok with aws feature: {:?}", result.err());
        #[cfg(not(feature = "bundle-upload-aws"))]
        assert!(matches!(result.unwrap_err(), BundleUploadError::FeatureNotEnabled { .. }));
    }

    #[test]
    fn rejects_gs_url_without_gcp_feature() {
        let err = from_url("gs://my-bucket/my-key/").unwrap_err();
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
```

- [ ] **Step 2: Run tests (will fail until Task 1.6 wires module)**

```bash
cargo test --lib bundle_upload::dispatcher::tests
```

Expected: compile error (module not in tree). Resolved next task.

- [ ] **Step 3: Commit**

```bash
git add src/bundle_upload/dispatcher.rs
git commit -m "feat(bundle-upload): add scheme-based dispatcher"
```

---

### Task 1.6: Wire `bundle_upload` module into the crate

**Files:**
- Create: `greentic-deployer/src/bundle_upload/mod.rs`
- Modify: `greentic-deployer/src/lib.rs`

- [ ] **Step 1: Write `mod.rs`**

```rust
// greentic-deployer/src/bundle_upload/mod.rs
//! Cloud bundle upload abstraction.
//!
//! See `docs/superpowers/specs/2026-05-07-gtc-bundle-upload-flag-design.md`.

mod dispatcher;
mod error;
mod uploader;
mod types;

#[cfg(feature = "bundle-upload-aws")]
pub mod s3;

#[cfg(feature = "bundle-upload-gcp")]
pub mod gcs;

#[cfg(feature = "bundle-upload-azure")]
pub mod azure;

pub use dispatcher::from_url;
pub use error::{BundleUploadError, BundleUploadResult};
pub use types::{UploadOptions, UploadedBundle};
pub use uploader::BundleUploader;
```

- [ ] **Step 2: Add module to `lib.rs`**

Find `pub mod aws;` in `greentic-deployer/src/lib.rs` and insert immediately after:

```rust
pub mod bundle_upload;
```

(Alphabetical placement keeps lib.rs tidy. Verify final ordering with `grep -n "^pub mod" src/lib.rs`.)

- [ ] **Step 3: Run dispatcher unit tests**

```bash
cargo test --lib bundle_upload::dispatcher::tests
```

Expected: 6 tests pass. Two of them (`accepts_s3_url_with_aws_feature`, `rejects_gs_url_without_gcp_feature`) gate on default features; verify both with:

```bash
cargo test --lib --no-default-features bundle_upload::dispatcher::tests
```

Expected: same 6 tests pass; `accepts_s3_url_with_aws_feature` exercises the `cfg(not)` branch.

- [ ] **Step 4: Run types unit tests**

```bash
cargo test --lib bundle_upload::types::tests
```

Expected: 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/bundle_upload/mod.rs src/lib.rs
git commit -m "feat(bundle-upload): wire bundle_upload module into lib"
```

---

## Phase 2A: S3Uploader implementation (after Phase 1)

### Task 2A.1: S3 URL parser

**Files:**
- Create: `greentic-deployer/src/bundle_upload/s3.rs` (initial scaffold; populated by subsequent tasks)

- [ ] **Step 1: Initial file with parser + tests**

```rust
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

pub struct S3Uploader {
    target: S3Target,
}

impl S3Uploader {
    pub fn from_url(url: &str) -> BundleUploadResult<Self> {
        Ok(Self {
            target: S3Target::parse(url)?,
        })
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
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test --lib bundle_upload::s3::tests
```

Expected: 7 tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/bundle_upload/s3.rs
git commit -m "feat(bundle-upload-aws): S3 URL parser + scaffold"
```

---

### Task 2A.2: SHA256 streaming digest helper

**Files:**
- Modify: `greentic-deployer/src/bundle_upload/s3.rs` (add `digest_file` helper at end of file before `#[cfg(test)] mod tests`)

- [ ] **Step 1: Add helper + test**

Insert the following just above `#[cfg(test)] mod tests`:

```rust
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
```

Add to the `tests` mod (after existing tests):

```rust
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
```

- [ ] **Step 2: Run new test**

```bash
cargo test --lib bundle_upload::s3::tests::digest_known_fixture
```

Expected: pass.

- [ ] **Step 3: Commit**

```bash
git add src/bundle_upload/s3.rs
git commit -m "feat(bundle-upload-aws): streaming SHA256 digest helper"
```

---

### Task 2A.3: AWS SDK client construction

**Files:**
- Modify: `greentic-deployer/src/bundle_upload/s3.rs`

- [ ] **Step 1: Add client construction helper**

Insert after the `S3Uploader` struct definition:

```rust
impl S3Uploader {
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
}
```

- [ ] **Step 2: Compile-check**

```bash
cargo check
```

Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add src/bundle_upload/s3.rs
git commit -m "feat(bundle-upload-aws): aws-config client construction"
```

---

### Task 2A.4: Bucket auto-create logic

**Files:**
- Modify: `greentic-deployer/src/bundle_upload/s3.rs`

- [ ] **Step 1: Add bucket-ensure helper**

Insert into the `impl S3Uploader` block:

```rust
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
```

- [ ] **Step 2: Compile-check**

```bash
cargo check
```

Expected: clean. (No unit test here; covered by integration test in Phase 5.)

- [ ] **Step 3: Commit**

```bash
git add src/bundle_upload/s3.rs
git commit -m "feat(bundle-upload-aws): bucket auto-create with private+versioned+SSE-S3"
```

---

### Task 2A.5: `upload` method with idempotency

**Files:**
- Modify: `greentic-deployer/src/bundle_upload/s3.rs`

- [ ] **Step 1: Replace placeholder `upload` impl**

In the `#[async_trait::async_trait] impl BundleUploader for S3Uploader` block, replace the body of `upload`:

```rust
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
                    return Err(BundleUploadError::Other(format!(
                        "head_object {}: {other:?}",
                        key
                    )));
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
                    BundleUploadError::Other(format!("put_object: {:?}", err.into_service_error()))
                })?;
        }

        let object_ref = format!("s3://{}/{}", self.target.bucket, key);
        let uploaded = self
            .presign_get(&client, &key, &full_digest, &object_ref, opts)
            .await?;
        Ok(uploaded)
    }
```

- [ ] **Step 2: Compile-check**

```bash
cargo check
```

Expected: error — `presign_get` not defined yet. Resolved in next task.

---

### Task 2A.6: Presign GET URL helper + completion of `upload` and `refresh_url`

**Files:**
- Modify: `greentic-deployer/src/bundle_upload/s3.rs`

- [ ] **Step 1: Add `presign_get` and finish `refresh_url`**

Insert into `impl S3Uploader` block:

```rust
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
                BundleUploadError::Other(format!("presign get_object: {:?}", err.into_service_error()))
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
```

Replace the body of `refresh_url`:

```rust
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
                if let aws_sdk_s3::operation::head_object::HeadObjectError::NotFound(_) =
                    err.into_service_error()
                {
                    BundleUploadError::ObjectMissing(object_ref.to_string())
                } else {
                    BundleUploadError::Other(format!("head_object {key}"))
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
```

- [ ] **Step 2: Run all unit tests**

```bash
cargo test --lib bundle_upload
```

Expected: all tests pass; no integration tests fail (those require LocalStack, run later).

- [ ] **Step 3: Commit**

```bash
git add src/bundle_upload/s3.rs
git commit -m "feat(bundle-upload-aws): implement upload + refresh_url with idempotency + presign"
```

---

## Phase 2B: GCS / Azure stub modules (parallel with 2A)

### Task 2B.1: GCS stub module

**Files:**
- Create: `greentic-deployer/src/bundle_upload/gcs.rs`

- [ ] **Step 1: Stub file**

```rust
// greentic-deployer/src/bundle_upload/gcs.rs
//! GCS implementation of `BundleUploader` (stub).
//!
//! Compiled only when the `bundle-upload-gcp` cargo feature is enabled.
//! Currently returns `unimplemented!()` for all operations; populated when
//! the first GCP demo deploy is needed.

use std::path::Path;

use super::error::{BundleUploadError, BundleUploadResult};
use super::types::{UploadOptions, UploadedBundle};
use super::uploader::BundleUploader;

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
```

- [ ] **Step 2: Compile-check with feature**

```bash
cargo check --features bundle-upload-gcp
```

Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add src/bundle_upload/gcs.rs
git commit -m "feat(bundle-upload-gcp): GcsUploader stub"
```

---

### Task 2B.2: Azure Blob stub module

**Files:**
- Create: `greentic-deployer/src/bundle_upload/azure.rs`

- [ ] **Step 1: Stub file**

```rust
// greentic-deployer/src/bundle_upload/azure.rs
//! Azure Blob implementation of `BundleUploader` (stub).
//!
//! Compiled only when the `bundle-upload-azure` cargo feature is enabled.

use std::path::Path;

use super::error::{BundleUploadError, BundleUploadResult};
use super::types::{UploadOptions, UploadedBundle};
use super::uploader::BundleUploader;

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
```

- [ ] **Step 2: Compile-check with feature**

```bash
cargo check --features bundle-upload-azure
```

Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add src/bundle_upload/azure.rs
git commit -m "feat(bundle-upload-azure): AzureUploader stub"
```

---

## Phase 2C: Deployer CLI subcommands (after Phase 1, parallel with 2A/2B)

### Task 2C.1: Add `BundleUpload` top-level command to deployer CLI

**Files:**
- Modify: `greentic-deployer/src/main.rs`

- [ ] **Step 1: Add enum variant**

In `enum TopLevelCommand` (around line 33–51), insert after `Aws(AwsCommand),`:

```rust
    BundleUpload(BundleUploadCommand),
```

After the existing `*Command` struct definitions, add:

```rust
#[derive(Parser)]
struct BundleUploadCommand {
    #[command(subcommand)]
    command: BundleUploadSubcommand,
}

#[derive(Subcommand)]
enum BundleUploadSubcommand {
    /// Upload a local bundle to cloud storage and emit a presigned/public URL.
    Upload(BundleUploadArgs),
    /// Re-issue a fresh URL for an already-uploaded bundle without re-uploading.
    RefreshUrl(BundleRefreshArgs),
}

#[derive(Parser)]
struct BundleUploadArgs {
    /// Cloud storage target URL: s3://bucket/prefix/, gs://..., https://*.blob.core.windows.net/...
    #[arg(long)]
    target: String,
    /// Path to local .gtbundle file.
    #[arg(long)]
    bundle: PathBuf,
    /// Presigned URL expiry in seconds (S3 hard-caps at 604800).
    #[arg(long, default_value_t = 604800)]
    presign_expires: u64,
}

#[derive(Parser)]
struct BundleRefreshArgs {
    /// Cloud-native object reference, e.g. `s3://bucket/key`.
    #[arg(long)]
    object_ref: String,
    /// Presigned URL expiry in seconds.
    #[arg(long, default_value_t = 604800)]
    presign_expires: u64,
}
```

- [ ] **Step 2: Compile-check**

```bash
cargo check
```

Expected: error — match arm for `BundleUpload` not exhaustive. Resolved next step.

- [ ] **Step 3: Add match arm in `main.rs` dispatcher**

Find the top-level dispatch `match cli.command { ... }` (search for `match cli.command`). Add:

```rust
TopLevelCommand::BundleUpload(cmd) => run_bundle_upload(cmd).await?,
```

Add the runner function at module scope:

```rust
async fn run_bundle_upload(cmd: BundleUploadCommand) -> anyhow::Result<()> {
    use greentic_deployer::bundle_upload::{from_url, UploadOptions};

    let opts = match &cmd.command {
        BundleUploadSubcommand::Upload(args) => UploadOptions {
            presign_expires_secs: args.presign_expires,
        },
        BundleUploadSubcommand::RefreshUrl(args) => UploadOptions {
            presign_expires_secs: args.presign_expires,
        },
    };

    let result = match cmd.command {
        BundleUploadSubcommand::Upload(args) => {
            let uploader = from_url(&args.target)?;
            uploader.upload(&args.bundle, &opts).await?
        }
        BundleUploadSubcommand::RefreshUrl(args) => {
            // Derive the uploader from the object_ref scheme (same dispatch).
            let uploader = from_url(&args.object_ref)?;
            uploader.refresh_url(&args.object_ref, &opts).await?
        }
    };

    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
```

- [ ] **Step 4: Compile-check + binary smoke test**

```bash
cargo build --bin greentic-deployer
./target/debug/greentic-deployer bundle-upload --help
```

Expected: help text shows `upload` and `refresh-url` subcommands.

- [ ] **Step 5: Commit**

```bash
git add src/main.rs
git commit -m "feat(bundle-upload): add greentic-deployer bundle-upload CLI subcommand"
```

---

## Phase 3: gtc CLI flag wiring (after Phase 2C)

### Task 3.1: Add `--upload-bundle` and `--upload-bundle-presign-expires` flags

**Files:**
- Modify: `greentic/src/bin/gtc/cli.rs`

- [ ] **Step 1: Define a flag-builder helper**

At a sensible spot in `cli.rs` (search for `fn build_command_args` or similar; if none, place after the use-imports block), add:

```rust
fn upload_bundle_args(options_heading: &str) -> Vec<Arg> {
    vec![
        Arg::new("upload-bundle")
            .long("upload-bundle")
            .value_name("URL")
            .num_args(1)
            .help_heading(options_heading)
            .help(
                "Upload local bundle to cloud storage and use as --deploy-bundle-source. \
                 Mutually exclusive with --deploy-bundle-source. \
                 Schemes: s3://, gs://, https://*.blob.core.windows.net/",
            )
            .conflicts_with("deploy-bundle-source"),
        Arg::new("upload-bundle-presign-expires")
            .long("upload-bundle-presign-expires")
            .value_name("SECONDS")
            .num_args(1)
            .default_value("604800")
            .help_heading(options_heading)
            .help("Presigned URL expiry in seconds (S3 hard-caps at 604800 = 7 days)"),
    ]
}
```

- [ ] **Step 2: Apply helper at every site that takes `--deploy-bundle-source`**

Search the file:

```bash
grep -n "deploy-bundle-source" /home/bima-pangestu/Works/greentic/greentic/src/bin/gtc/cli.rs
```

Identify the single occurrence (cli.rs:738) — currently only the `start` subcommand wires `--deploy-bundle-source`. After the existing `.arg(...)` for `deploy-bundle-source`, insert:

```rust
                .args(upload_bundle_args(options_heading))
```

- [ ] **Step 3: Compile-check**

```bash
cd /home/bima-pangestu/Works/greentic/greentic
cargo check -p gtc
```

Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add src/bin/gtc/cli.rs
git commit -m "feat(gtc): add --upload-bundle and --upload-bundle-presign-expires flags"
```

---

### Task 3.2: Parse new flags in `start_stop.rs`

**Files:**
- Modify: `greentic/src/bin/gtc/deploy.rs` (option struct)
- Modify: `greentic/src/bin/gtc/deploy/start_stop.rs` (parser)

- [ ] **Step 1: Add fields to options struct**

In `greentic/src/bin/gtc/deploy.rs`, find `pub(super) struct StartCliOptions` (line 63) and add fields:

```rust
    pub(super) upload_bundle: Option<String>,
    pub(super) upload_bundle_presign_expires: Option<u64>,
```

- [ ] **Step 2: Parse them in `start_stop.rs`**

In `greentic/src/bin/gtc/deploy/start_stop.rs`, find the parser around line 302 (`let mut deploy_bundle_source = None;` block) and add:

```rust
    let mut upload_bundle: Option<String> = None;
    let mut upload_bundle_presign_expires: Option<u64> = None;
```

In the matching loop, alongside the existing `--deploy-bundle-source` handler, add (using the same pattern):

```rust
            "--upload-bundle" => {
                idx += 1;
                upload_bundle = Some(required_value(tail, idx, "--upload-bundle")?);
            }
            "--upload-bundle-presign-expires" => {
                idx += 1;
                let raw = required_value(tail, idx, "--upload-bundle-presign-expires")?;
                upload_bundle_presign_expires = Some(
                    raw.parse::<u64>()
                        .map_err(|e| GtcError::message(format!("invalid --upload-bundle-presign-expires: {e}")))?,
                );
            }
```

Also handle the `--upload-bundle=value` shorthand alongside the existing `--deploy-bundle-source=` handler (mirror exactly).

In the `StartCliOptions` constructor at the end of the function, add:

```rust
    upload_bundle,
    upload_bundle_presign_expires,
```

- [ ] **Step 3: Add validation: mutual exclusivity**

Right after the parser loop, before constructing `StartCliOptions`, add:

```rust
    if upload_bundle.is_some() && deploy_bundle_source.is_some() {
        return Err(GtcError::message(
            "--upload-bundle and --deploy-bundle-source are mutually exclusive; pick one"
                .to_string(),
        ));
    }
```

- [ ] **Step 4: Compile-check**

```bash
cargo check -p gtc
```

Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add src/bin/gtc/deploy.rs src/bin/gtc/deploy/start_stop.rs
git commit -m "feat(gtc): parse --upload-bundle flags in start subcommand"
```

---

### Task 3.3: Bundle upload orchestrator helper

**Files:**
- Create: `greentic/src/bin/gtc/deploy/bundle_upload_orchestrator.rs`
- Modify: `greentic/src/bin/gtc/deploy.rs` (add `mod` declaration)

- [ ] **Step 1: Create orchestrator file**

```rust
// greentic/src/bin/gtc/deploy/bundle_upload_orchestrator.rs
//! Spawns `greentic-start warmup` and `greentic-deployer bundle-upload upload`
//! to bridge a local `.gtbundle` to a remote URL + digest pair consumable by
//! the existing deploy flow.

use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use serde::Deserialize;

use crate::error::{GtcError, GtcResult};

#[derive(Debug, Clone, Deserialize)]
pub struct UploadedBundle {
    pub url: String,
    pub digest: String,
    pub expires_at: Option<String>,
    pub object_ref: String,
}

/// Detect whether a bundle file is already warmed by checking the filename
/// pattern `bundle-warmed-*.gtbundle`. Conservative: any other name triggers
/// a fresh warmup pass.
pub fn is_warmed(bundle_path: &Path) -> bool {
    bundle_path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|name| name.starts_with("bundle-warmed-"))
        .unwrap_or(false)
}

/// Spawn `greentic-start warmup --bundle <input> --output <out>` and return the warmed path.
pub fn warmup_bundle(input: &Path, out_dir: &Path) -> GtcResult<PathBuf> {
    let warmed = out_dir.join("bundle-warmed.gtbundle");
    let status = ProcessCommand::new("greentic-start")
        .arg("warmup")
        .arg("--bundle")
        .arg(input)
        .arg("--output")
        .arg(&warmed)
        .status()
        .map_err(|e| {
            GtcError::message(format!(
                "failed to spawn greentic-start warmup: {e}. Install greentic-start and ensure it is on PATH."
            ))
        })?;
    if !status.success() {
        return Err(GtcError::message(format!(
            "greentic-start warmup exited with status {:?}",
            status.code()
        )));
    }
    Ok(warmed)
}

/// Spawn `greentic-deployer bundle-upload upload --target <url> --bundle <path> --presign-expires <secs>`
/// and parse JSON stdout into `UploadedBundle`.
pub fn upload_bundle(
    target: &str,
    bundle: &Path,
    presign_expires: u64,
) -> GtcResult<UploadedBundle> {
    let output = ProcessCommand::new("greentic-deployer")
        .arg("bundle-upload")
        .arg("upload")
        .arg("--target")
        .arg(target)
        .arg("--bundle")
        .arg(bundle)
        .arg("--presign-expires")
        .arg(presign_expires.to_string())
        .output()
        .map_err(|e| {
            GtcError::message(format!(
                "failed to spawn greentic-deployer bundle-upload: {e}. Install with `cargo install greentic-deployer`."
            ))
        })?;
    if !output.status.success() {
        return Err(GtcError::message(format!(
            "greentic-deployer bundle-upload upload failed (exit {:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    serde_json::from_slice::<UploadedBundle>(&output.stdout)
        .map_err(|e| GtcError::message(format!("invalid JSON from greentic-deployer bundle-upload: {e}")))
}

/// Spawn `greentic-deployer bundle-upload refresh-url --object-ref <ref> --presign-expires <secs>`
/// and parse JSON stdout into `UploadedBundle`.
pub fn refresh_bundle_url(object_ref: &str, presign_expires: u64) -> GtcResult<UploadedBundle> {
    let output = ProcessCommand::new("greentic-deployer")
        .arg("bundle-upload")
        .arg("refresh-url")
        .arg("--object-ref")
        .arg(object_ref)
        .arg("--presign-expires")
        .arg(presign_expires.to_string())
        .output()
        .map_err(|e| {
            GtcError::message(format!(
                "failed to spawn greentic-deployer bundle-upload refresh-url: {e}"
            ))
        })?;
    if !output.status.success() {
        return Err(GtcError::message(format!(
            "greentic-deployer bundle-upload refresh-url failed (exit {:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    serde_json::from_slice::<UploadedBundle>(&output.stdout)
        .map_err(|e| GtcError::message(format!("invalid JSON from refresh-url: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_warmed_bundle_filename() {
        assert!(is_warmed(Path::new("bundle-warmed-0.5.18-keyed-1113.gtbundle")));
        assert!(is_warmed(Path::new("/some/path/bundle-warmed-foo.gtbundle")));
    }

    #[test]
    fn detects_unwarmed_bundle_filename() {
        assert!(!is_warmed(Path::new("deep-research-demo-bundle.gtbundle")));
        assert!(!is_warmed(Path::new("bundle.gtbundle")));
    }
}
```

- [ ] **Step 2: Wire as module in deploy.rs**

In `greentic/src/bin/gtc/deploy.rs`, add at the top with other `#[path = "..."] mod ...` declarations:

```rust
#[path = "deploy/bundle_upload_orchestrator.rs"]
mod bundle_upload_orchestrator;
```

- [ ] **Step 3: Run unit tests**

```bash
cargo test -p gtc bundle_upload_orchestrator::tests
```

Expected: 2 tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/bin/gtc/deploy/bundle_upload_orchestrator.rs src/bin/gtc/deploy.rs
git commit -m "feat(gtc): bundle upload orchestrator (spawn warmup + deployer subprocess)"
```

---

### Task 3.4: Pre-deploy hook integration

**Files:**
- Modify: `greentic/src/bin/gtc/deploy/cloud_deploy.rs`

- [ ] **Step 1: Locate the hook site**

Search `greentic/src/bin/gtc/deploy/cloud_deploy.rs` for `validate_cloud_deploy_inputs` (line 54). The new logic plugs in just before this validation, so the synthesized `--deploy-bundle-source` is the value the validator sees.

- [ ] **Step 2: Add the hook function**

Insert at the bottom of the file:

```rust
use crate::deploy::bundle_upload_orchestrator;

/// If `--upload-bundle` is set, run warmup + deployer upload subprocess and
/// return the URL + digest to be injected into the standard deploy flow.
/// Returns `(remote_url, digest)`.
pub(crate) fn resolve_upload_bundle(
    bundle_dir: &Path,
    upload_bundle: &str,
    presign_expires: u64,
) -> GtcResult<(String, String)> {
    use std::env;
    use tempfile::TempDir;

    // Locate the local .gtbundle. The CLI accepts a bundle-ref that can resolve
    // to either a directory (with bundle.yaml) or a .gtbundle file. Reuse the
    // existing fingerprinter to find the .gtbundle in the bundle's dist/ dir.
    let gtbundle_path = locate_gtbundle_in_bundle_dir(bundle_dir).ok_or_else(|| {
        GtcError::message(format!(
            "could not locate .gtbundle inside {}; build the bundle first",
            bundle_dir.display()
        ))
    })?;

    // Warm if not already warmed.
    let warmed_path = if bundle_upload_orchestrator::is_warmed(&gtbundle_path) {
        gtbundle_path
    } else {
        let tmp = env::temp_dir().join("gtc-warmup");
        std::fs::create_dir_all(&tmp).ok();
        bundle_upload_orchestrator::warmup_bundle(&gtbundle_path, &tmp)?
    };

    let result = bundle_upload_orchestrator::upload_bundle(
        upload_bundle,
        &warmed_path,
        presign_expires,
    )?;

    eprintln!("Uploaded bundle:");
    eprintln!("  digest:      {}", result.digest);
    eprintln!("  url:         {}", result.url);
    if let Some(exp) = result.expires_at.as_ref() {
        eprintln!("  expires:     {exp}");
    }
    eprintln!("  object ref:  {}", result.object_ref);
    eprintln!("To refresh URL without re-uploading: gtc deploy refresh-bundle-url");

    Ok((result.url, result.digest))
}

/// Locate a `*.gtbundle` file inside the bundle's `dist/` directory.
/// Prefers `bundle-warmed-*.gtbundle` over plain ones.
fn locate_gtbundle_in_bundle_dir(bundle_dir: &Path) -> Option<PathBuf> {
    let dist = bundle_dir.join("dist");
    let entries = std::fs::read_dir(&dist).ok()?;
    let mut best: Option<PathBuf> = None;
    let mut best_warmed = false;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("gtbundle") {
            let is_warmed = path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("bundle-warmed-"))
                .unwrap_or(false);
            if best.is_none() || (is_warmed && !best_warmed) {
                best = Some(path);
                best_warmed = is_warmed;
            }
        }
    }
    best
}
```

(`use std::path::{Path, PathBuf};` and the bundle_upload_orchestrator import may need to be added at the top of the file if not already present; check imports first.)

- [ ] **Step 3: Wire hook into the start path**

Find `run_start` or the function that consumes `StartCliOptions` (search for the use of `deploy_bundle_source` field). Just before the existing call site that synthesizes `--deploy-bundle-source` into the args vector, add:

```rust
    let synthesized_source: Option<(String, String)> = if let Some(upload_target) =
        opts.upload_bundle.as_deref()
    {
        let presign = opts.upload_bundle_presign_expires.unwrap_or(604800);
        let bundle_root = /* existing variable for the local bundle directory */;
        let (url, digest) = resolve_upload_bundle(bundle_root, upload_target, presign)?;
        Some((url, digest))
    } else {
        None
    };
```

Then where the args vector is built and `--deploy-bundle-source <value>` would normally be appended, branch:

```rust
    if let Some((url, digest)) = &synthesized_source {
        args.push("--deploy-bundle-source".to_string());
        args.push(url.clone());
        args.push("--bundle-digest".to_string());
        args.push(digest.clone());
    } else if let Some(src) = opts.deploy_bundle_source.as_deref() {
        args.push("--deploy-bundle-source".to_string());
        args.push(src.to_string());
    }
```

(The exact integration site depends on the current shape of `run_start` — read it once before editing. The behavior contract: if `synthesized_source` is `Some`, use it; else fall back to existing `deploy_bundle_source`.)

- [ ] **Step 4: Compile-check**

```bash
cargo check -p gtc
```

Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add src/bin/gtc/deploy/cloud_deploy.rs
git commit -m "feat(gtc): pre-deploy hook resolves --upload-bundle into deploy-bundle-source"
```

---

## Phase 4: gtc deploy refresh-bundle-url subcommand (after Phase 2C)

### Task 4.1: Add `gtc deploy` parent + `refresh-bundle-url` child

**Files:**
- Modify: `greentic/src/bin/gtc/cli.rs`

- [ ] **Step 1: Add subcommand tree**

Add a new top-level subcommand block alongside `start`, `stop`, etc.:

```rust
        .subcommand(
            Command::new("deploy")
                .help_template(help_template)
                .subcommand_help_heading(commands_heading)
                .disable_help_flag(true)
                .disable_version_flag(true)
                .about("Manage cloud deploys (refresh URLs, status, etc.)")
                .subcommand(
                    Command::new("refresh-bundle-url")
                        .help_template(help_template)
                        .disable_help_flag(true)
                        .disable_version_flag(true)
                        .about(
                            "Re-issue a fresh presigned URL for an already-uploaded bundle and re-apply terraform.",
                        )
                        .arg(
                            Arg::new("bundle-ref")
                                .value_name("BUNDLE_REF")
                                .required(true)
                                .help_heading(arguments_heading)
                                .help("Bundle path/ref previously deployed via --upload-bundle"),
                        )
                        .arg(
                            Arg::new("cloud")
                                .long("cloud")
                                .value_name("PROVIDER")
                                .num_args(1)
                                .value_parser(["aws", "azure", "gcp"])
                                .help_heading(options_heading)
                                .help("Cloud provider (auto-detected from deploy state if omitted)"),
                        )
                        .arg(
                            Arg::new("environment")
                                .long("environment")
                                .value_name("ENV")
                                .num_args(1)
                                .default_value("dev")
                                .help_heading(options_heading)
                                .help("Environment name used during the original deploy"),
                        )
                        .arg(
                            Arg::new("upload-bundle-presign-expires")
                                .long("upload-bundle-presign-expires")
                                .value_name("SECONDS")
                                .num_args(1)
                                .default_value("604800")
                                .help_heading(options_heading)
                                .help("Presigned URL expiry in seconds"),
                        ),
                ),
        )
```

- [ ] **Step 2: Compile-check**

```bash
cargo check -p gtc
```

Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add src/bin/gtc/cli.rs
git commit -m "feat(gtc): add gtc deploy refresh-bundle-url subcommand to CLI tree"
```

---

### Task 4.2: Refresh subcommand implementation

**Files:**
- Create: `greentic/src/bin/gtc/deploy/refresh.rs`
- Modify: `greentic/src/bin/gtc/deploy.rs` (add module)
- Modify: `greentic/src/bin/gtc/router.rs` (dispatch)

- [ ] **Step 1: Create `refresh.rs`**

```rust
// greentic/src/bin/gtc/deploy/refresh.rs
//! `gtc deploy refresh-bundle-url <bundle-ref>` implementation.
//!
//! Spawns `greentic-deployer bundle-upload refresh-url` to re-issue a presigned
//! URL, rewrites `dev.tfvars` with the new URL, and runs the deploy state's
//! `terraform-apply.sh` to roll the operator task definition.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use crate::deploy::bundle_upload_orchestrator;
use crate::error::{GtcError, GtcResult};

pub struct RefreshArgs {
    pub bundle_ref: String,
    pub cloud: Option<String>,
    pub environment: String,
    pub presign_expires: u64,
}

pub fn run_refresh(args: RefreshArgs) -> GtcResult<()> {
    let deploy_state = resolve_deploy_state(&args.bundle_ref, args.cloud.as_deref(), &args.environment)?;
    let tfvars_path = deploy_state.join("terraform").join("dev.tfvars");
    let tfvars_text = fs::read_to_string(&tfvars_path).map_err(|e| {
        GtcError::message(format!("read tfvars {}: {e}", tfvars_path.display()))
    })?;

    let bundle_source = extract_tfvars_value(&tfvars_text, "bundle_source").ok_or_else(|| {
        GtcError::message(format!("bundle_source not found in {}", tfvars_path.display()))
    })?;
    let object_ref = derive_object_ref_from_url(&bundle_source).ok_or_else(|| {
        GtcError::message(format!(
            "could not derive object_ref from bundle_source URL: {bundle_source}"
        ))
    })?;

    let refreshed = bundle_upload_orchestrator::refresh_bundle_url(&object_ref, args.presign_expires)?;

    let updated = replace_tfvars_value(&tfvars_text, "bundle_source", &refreshed.url);
    fs::write(&tfvars_path, updated)
        .map_err(|e| GtcError::message(format!("write tfvars {}: {e}", tfvars_path.display())))?;

    eprintln!("Refreshed bundle URL:");
    eprintln!("  url:     {}", refreshed.url);
    if let Some(exp) = refreshed.expires_at.as_ref() {
        eprintln!("  expires: {exp}");
    }

    let apply_script = deploy_state.join("terraform-apply.sh");
    eprintln!("Running {} (ECS task replacement; ~5 min)...", apply_script.display());
    let status = ProcessCommand::new(&apply_script)
        .status()
        .map_err(|e| GtcError::message(format!("spawn terraform-apply.sh: {e}")))?;
    if !status.success() {
        return Err(GtcError::message(format!(
            "terraform-apply.sh exited with {:?}",
            status.code()
        )));
    }
    Ok(())
}

/// Resolve the deploy state directory under `~/.greentic/deploy/<cloud>/<env>/<bundle-fingerprint>/`.
fn resolve_deploy_state(
    bundle_ref: &str,
    cloud: Option<&str>,
    environment: &str,
) -> GtcResult<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| GtcError::message("home dir not found".to_string()))?;
    let deploy_root = home.join(".greentic").join("deploy");
    let fingerprint = mangle_bundle_ref_to_fingerprint(bundle_ref);

    let candidates: Vec<PathBuf> = if let Some(c) = cloud {
        vec![deploy_root.join(c).join(environment).join(&fingerprint)]
    } else {
        let mut out = Vec::new();
        for cloud_name in ["aws", "azure", "gcp"] {
            let path = deploy_root.join(cloud_name).join(environment).join(&fingerprint);
            if path.exists() {
                out.push(path);
            }
        }
        out
    };

    match candidates.len() {
        0 => Err(GtcError::message(format!(
            "no deploy state found for bundle {bundle_ref} (env={environment}); looked under {}",
            deploy_root.display()
        ))),
        1 => Ok(candidates.into_iter().next().unwrap()),
        n => {
            let list = candidates
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join("\n  ");
            Err(GtcError::message(format!(
                "{n} deploy states match bundle {bundle_ref}; pass --cloud to disambiguate:\n  {list}"
            )))
        }
    }
}

/// Mangle a bundle ref into the directory name the deployer uses under
/// `~/.greentic/deploy/<cloud>/<env>/`. The deployer replaces `/`, `-`, and
/// non-alphanumerics with `-` and prepends the path. We mirror that exactly.
fn mangle_bundle_ref_to_fingerprint(bundle_ref: &str) -> String {
    let cleaned = bundle_ref
        .replace(['/', '\\'], "-")
        .replace("..", "-")
        .replace(' ', "-");
    cleaned.trim_start_matches('-').to_string()
}

fn extract_tfvars_value(tfvars: &str, key: &str) -> Option<String> {
    for line in tfvars.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix(key) {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                let rest = rest.trim();
                if rest.starts_with('"') && rest.ends_with('"') && rest.len() >= 2 {
                    return Some(rest[1..rest.len() - 1].to_string());
                }
            }
        }
    }
    None
}

fn replace_tfvars_value(tfvars: &str, key: &str, new_value: &str) -> String {
    let mut out = String::with_capacity(tfvars.len());
    let mut replaced = false;
    for line in tfvars.lines() {
        let trimmed = line.trim_start();
        if !replaced && trimmed.starts_with(key) {
            out.push_str(&format!("{key} = \"{new_value}\""));
            out.push('\n');
            replaced = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Convert a presigned S3 URL `https://<bucket>.s3.<region>.amazonaws.com/<key>?...`
/// (or virtual-host-style with port) back into `s3://<bucket>/<key>`.
fn derive_object_ref_from_url(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    let path = parsed.path().trim_start_matches('/');
    if let Some(bucket) = host.strip_suffix(".s3.amazonaws.com") {
        return Some(format!("s3://{bucket}/{path}"));
    }
    if let Some(rest) = host.strip_prefix(".s3-") {
        let _ = rest;
    }
    // Virtual host: <bucket>.s3.<region>.amazonaws.com
    if let Some((bucket, suffix)) = host.split_once(".s3.") {
        if suffix.ends_with(".amazonaws.com") {
            return Some(format!("s3://{bucket}/{path}"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_existing_tfvars_value() {
        let text = r#"
cloud = "aws"
bundle_source = "https://example.com/old"
bundle_digest = "sha256:abc"
"#;
        assert_eq!(
            extract_tfvars_value(text, "bundle_source").as_deref(),
            Some("https://example.com/old")
        );
    }

    #[test]
    fn replace_tfvars_value_replaces_first_occurrence() {
        let text = r#"cloud = "aws"
bundle_source = "https://old/url"
bundle_digest = "sha256:abc"
"#;
        let updated = replace_tfvars_value(text, "bundle_source", "https://new/url");
        assert!(updated.contains(r#"bundle_source = "https://new/url""#));
        assert!(!updated.contains(r#""https://old/url""#));
    }

    #[test]
    fn derive_object_ref_from_virtual_host_url() {
        let url = "https://my-bucket.s3.eu-north-1.amazonaws.com/path/to/key.gtbundle?X-Amz-Signature=abc";
        assert_eq!(
            derive_object_ref_from_url(url).as_deref(),
            Some("s3://my-bucket/path/to/key.gtbundle")
        );
    }

    #[test]
    fn derive_object_ref_returns_none_for_non_s3() {
        assert!(derive_object_ref_from_url("https://example.com/x").is_none());
    }

    #[test]
    fn mangle_bundle_ref_replaces_slashes_and_dots() {
        let r = mangle_bundle_ref_to_fingerprint("/home/user/foo/bar.gtbundle");
        assert!(!r.contains('/'));
    }
}
```

- [ ] **Step 2: Wire module into `deploy.rs`**

In `greentic/src/bin/gtc/deploy.rs`, add:

```rust
#[path = "deploy/refresh.rs"]
mod refresh;
```

Add `pub use refresh::{run_refresh, RefreshArgs};` near the other re-exports.

- [ ] **Step 3: Add `dirs` crate dep**

In `greentic/Cargo.toml`, ensure `dirs = "5"` is in `[dependencies]` (check first; if absent, add).

```bash
cd /home/bima-pangestu/Works/greentic/greentic
grep -n "^dirs" Cargo.toml || echo "needs add"
```

If "needs add" shown:

```toml
dirs = "5"
```

- [ ] **Step 4: Wire dispatch in router**

In `greentic/src/bin/gtc/router.rs`, find the top-level subcommand match (search for `"start"` arm). Add a new arm:

```rust
        Some(("deploy", deploy_matches)) => {
            match deploy_matches.subcommand() {
                Some(("refresh-bundle-url", m)) => {
                    let args = crate::deploy::RefreshArgs {
                        bundle_ref: m.get_one::<String>("bundle-ref").cloned().unwrap_or_default(),
                        cloud: m.get_one::<String>("cloud").cloned(),
                        environment: m
                            .get_one::<String>("environment")
                            .cloned()
                            .unwrap_or_else(|| "dev".to_string()),
                        presign_expires: m
                            .get_one::<String>("upload-bundle-presign-expires")
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(604800),
                    };
                    crate::deploy::run_refresh(args)
                }
                _ => Err(GtcError::message(
                    "use: gtc deploy refresh-bundle-url <BUNDLE_REF>".to_string(),
                )),
            }
        }
```

- [ ] **Step 5: Run unit tests**

```bash
cargo test -p gtc deploy::refresh::tests
```

Expected: 5 tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/bin/gtc/deploy/refresh.rs src/bin/gtc/deploy.rs src/bin/gtc/router.rs Cargo.toml Cargo.lock
git commit -m "feat(gtc): implement deploy refresh-bundle-url subcommand"
```

---

## Phase 5: Integration tests (after Phase 2A)

### Task 5.1: LocalStack S3 happy-path test

**Files:**
- Create: `greentic-deployer/tests/bundle_upload_s3_localstack.rs`

- [ ] **Step 1: Create the test file**

```rust
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

use greentic_deployer::bundle_upload::{from_url, BundleUploadError, UploadOptions};

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
    assert!(result.object_ref.starts_with("s3://test-happy-path-bucket/"));
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
    let r1 = uploader.upload(bundle.path(), &opts).await.expect("first upload");
    let r2 = uploader.upload(bundle.path(), &opts).await.expect("second upload");
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
        .refresh_url("s3://test-missing-bucket/bundles/does-not-exist.gtbundle", &opts)
        .await
        .unwrap_err();
    assert!(matches!(err, BundleUploadError::ObjectMissing(_)));
}
```

- [ ] **Step 2: Run with LocalStack (manual / CI)**

```bash
docker run --rm -d --name localstack -p 4566:4566 localstack/localstack:latest
sleep 5
LOCALSTACK_ENDPOINT=http://localhost:4566 cargo test --features bundle-upload-aws \
  --test bundle_upload_s3_localstack
docker stop localstack
```

Expected: 4 tests pass.

- [ ] **Step 3: Commit**

```bash
git add tests/bundle_upload_s3_localstack.rs
git commit -m "test(bundle-upload-aws): LocalStack integration tests"
```

---

## Phase 6: Docs + verification

### Task 6.1: Update deployer README + docs

**Files:**
- Modify: `greentic-deployer/README.md`
- Modify: `greentic-deployer/docs/deployment-packs.md` (or wherever cloud doc lives — verify)

- [ ] **Step 1: Add a section to the deployer README**

Append a new section to `greentic-deployer/README.md`:

```markdown
## Bundle upload (`bundle-upload` subcommand)

The deployer can upload a local `.gtbundle` to cloud object storage and emit a
fetchable URL + content digest as JSON, intended for use as the
`--deploy-bundle-source` input to `gtc start --cloud aws`.

```bash
greentic-deployer bundle-upload upload \
  --target s3://my-bundle-bucket/path/ \
  --bundle ./dist/bundle-warmed-0.5.18.gtbundle \
  --presign-expires 604800
```

JSON output:

```json
{
  "url": "https://...presigned...",
  "digest": "sha256:abc...",
  "expires_at": "2026-05-14T07:18:32Z",
  "object_ref": "s3://my-bundle-bucket/path/abc123.gtbundle"
}
```

To refresh the presigned URL on an already-uploaded bundle (e.g. weekly cron):

```bash
greentic-deployer bundle-upload refresh-url \
  --object-ref s3://my-bundle-bucket/path/abc123.gtbundle
```

Cargo features:

- `bundle-upload-aws` — default-on. S3 implementation.
- `bundle-upload-gcp` — off. GCS stub.
- `bundle-upload-azure` — off. Azure Blob stub.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: bundle-upload subcommand + cargo feature flags"
```

---

### Task 6.2: Update gtc help i18n strings

**Files:**
- Modify: `greentic/i18n/en.json` (and verify whether translate script needs to run)

- [ ] **Step 1: Add help-text keys**

Find existing `gtc.arg.deploy_bundle_source.help` in `greentic/i18n/en.json` and add neighbours:

```json
"gtc.arg.upload_bundle.help": "Upload local bundle to cloud storage and use as --deploy-bundle-source. Mutually exclusive with --deploy-bundle-source.",
"gtc.arg.upload_bundle_presign_expires.help": "Presigned URL expiry in seconds (S3 hard-caps at 604800 = 7 days)",
"gtc.cmd.deploy.about": "Manage cloud deploys (refresh URLs, status, etc.)",
"gtc.cmd.deploy_refresh.about": "Re-issue a fresh presigned URL for an already-uploaded bundle and re-apply terraform."
```

Update `cli.rs` help-text strings (Tasks 3.1, 4.1) to use `t(locale, "...")` lookups instead of hard-coded English.

- [ ] **Step 2: Run translation script (if Bima opts in; else leave for follow-up)**

```bash
LANGS=all BATCH_SIZE=200 bash tools/i18n.sh
```

(skip if not authorized; leave a TODO note in PR description.)

- [ ] **Step 3: Commit**

```bash
git add i18n/en.json src/bin/gtc/cli.rs
git commit -m "i18n: add upload-bundle + deploy refresh help strings"
```

---

### Task 6.3: Run `local_check.sh` + fix lint

**Files:**
- (none)

- [ ] **Step 1: Deployer**

```bash
cd /home/bima-pangestu/Works/greentic/greentic-deployer
bash ci/local_check.sh
```

Expected: pass. If clippy warns, fix and re-run.

- [ ] **Step 2: gtc**

```bash
cd /home/bima-pangestu/Works/greentic/greentic
bash ci/local_check.sh
```

Expected: pass.

- [ ] **Step 3: Commit any lint fixes**

```bash
git add -p
git commit -m "chore: lint fixes from local_check"
```

(only if needed.)

---

### Task 6.4: Manual verification against deep-research-demo-bundle

**Files:**
- (none — manual exercise)

- [ ] **Step 1: Build both binaries**

```bash
cd /home/bima-pangestu/Works/greentic/greentic-deployer
cargo install --path . --force

cd /home/bima-pangestu/Works/greentic/greentic
cargo install --path . --force
```

- [ ] **Step 2: One-command deploy attempt**

```bash
gtc start /home/bima-pangestu/Works/greentic/deep-research-demo-bundle \
  --cloud aws \
  --upload-bundle s3://greentic-deep-research-local-20260430-vahe/auto-deploy/
```

Expected: stderr shows warmup → upload → URL summary; terraform-apply runs to completion; operator endpoint printed at the end.

- [ ] **Step 3: Refresh attempt**

```bash
gtc deploy refresh-bundle-url /home/bima-pangestu/Works/greentic/deep-research-demo-bundle --cloud aws
```

Expected: refresh-url subprocess returns new URL; tfvars updated; terraform-apply rolls task; ECS task replaced within ~5min.

- [ ] **Step 4: Note results in PR description**

(no commit; just gather findings to paste into PR.)

---

### Task 6.5: Push + open PRs

**Files:**
- (none)

- [ ] **Step 1: Push deployer branch**

```bash
cd /home/bima-pangestu/Works/greentic/greentic-deployer
git push -u origin feat/gtc-bundle-upload-flag
```

- [ ] **Step 2: Open deployer PR**

```bash
gh pr create --base main --title "feat(bundle-upload): trait + S3 impl + bundle-upload CLI" --body "$(cat <<'EOF'
## Summary
- Adds `BundleUploader` trait + `S3Uploader` impl in `src/bundle_upload/`.
- Exposes via `greentic-deployer bundle-upload {upload,refresh-url}` CLI subcommand emitting JSON.
- Cargo features: `bundle-upload-aws` (default), `bundle-upload-gcp` (stub), `bundle-upload-azure` (stub).

Spec: `docs/superpowers/specs/2026-05-07-gtc-bundle-upload-flag-design.md`
Plan: `docs/superpowers/plans/2026-05-07-gtc-bundle-upload-flag.md`

## Test plan
- [ ] `bash ci/local_check.sh` clean
- [ ] LocalStack integration tests pass (`LOCALSTACK_ENDPOINT=http://localhost:4566 cargo test --features bundle-upload-aws --test bundle_upload_s3_localstack`)
- [ ] Manual: `greentic-deployer bundle-upload upload --target s3://test-bucket/ --bundle <path>` against a test AWS account
EOF
)"
```

- [ ] **Step 3: Push gtc branch**

```bash
cd /home/bima-pangestu/Works/greentic/greentic
git push -u origin feat/gtc-upload-bundle-flag
```

- [ ] **Step 4: Open gtc PR (after deployer PR merged)**

```bash
gh pr create --base main --title "feat(gtc): --upload-bundle flag + gtc deploy refresh-bundle-url" --body "$(cat <<'EOF'
## Summary
- Adds `--upload-bundle <URL>` flag to `gtc start` (mutually exclusive with `--deploy-bundle-source`).
- Adds `gtc deploy refresh-bundle-url <bundle-ref>` subcommand.
- Spawns `greentic-deployer bundle-upload` and `greentic-start warmup` subprocesses (no direct crate deps).

Depends on greentic-deployer#XXX (link to merged PR).

## Test plan
- [ ] `bash ci/local_check.sh` clean
- [ ] Manual: end-to-end deploy of deep-research-demo-bundle from a single command
- [ ] Manual: refresh-bundle-url after 6 days against the same deploy
EOF
)"
```

---

## Self-Review

- [x] **Spec coverage:**
  - Trait + S3 impl + dispatcher → Phase 1 + 2A
  - GCS / Azure stubs → Phase 2B
  - Cargo feature flags → Task 1.1
  - `gtc start --upload-bundle` flag → Phase 3
  - Auto-warmup spawn → Task 3.3
  - Auto-create bucket → Task 2A.4
  - Idempotent re-run → Task 2A.5
  - `gtc deploy refresh-bundle-url` → Phase 4
  - LocalStack integration tests → Phase 5
  - Docs update → Task 6.1, 6.2
  - Spec → all linked
- [x] **No placeholders:** every task has concrete code blocks; the only abstract step is in Task 3.4 ("the existing variable for the local bundle directory") which is unavoidable until the implementing engineer reads the surrounding function — covered by the explicit instruction to read the function before editing.
- [x] **Type consistency:**
  - `UploadedBundle.url`, `.digest`, `.expires_at`, `.object_ref` consistent in deployer types, JSON output, gtc orchestrator deserializer, and refresh subcommand parser.
  - `BundleUploader::upload(bundle_path, opts)` signature consistent.
  - Cargo feature names consistent (`bundle-upload-aws/-gcp/-azure`) across Task 1.1, 2A scaffold, dispatcher, mod.rs, integration test cfg.
  - `presign_expires_secs` / `presign-expires` flag-name consistent.
  - `--target` / `--bundle` / `--object-ref` / `--presign-expires` deployer CLI flag names consistent across deployer and gtc orchestrator.

## Execution choice

Plan complete and saved to `greentic-deployer/docs/superpowers/plans/2026-05-07-gtc-bundle-upload-flag.md`.

Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task with two-stage review. Best for parallel-safe phases (2A + 2B + 2C).
2. **Inline Execution** — execute tasks in this session with checkpoints. Slower wall-clock but simpler hand-back.

Which approach?
