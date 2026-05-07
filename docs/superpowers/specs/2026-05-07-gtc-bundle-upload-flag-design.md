# gtc Bundle Upload Flag — Design

**Date:** 2026-05-07
**Status:** Proposed
**Owner:** @bimapangestu28
**Reviewers:** @VaheGrishkyan (cloud publish), devops

## Summary

Add a `--upload-bundle <URL>` flag to `gtc start --cloud {aws,gcp,azure}` that takes a local `.gtbundle` path, auto-warms the bundle, uploads it to cloud object storage, computes its digest, and feeds the resulting URL + digest into the existing deploy flow as `--deploy-bundle-source` and `--bundle-digest`. Replaces a five-step manual recipe (warmup → `aws s3 cp` → `aws s3 presign` → `sha256sum` → edit `dev.tfvars`) with a single command.

A `BundleUploader` trait abstracts the cloud-specific storage logic so the same flag works against S3, GCS, and Azure Blob in the future. AWS / S3 is the only implementor delivered in this phase. The GCS and Azure Blob modules exist on disk but are gated behind cargo features `bundle-upload-gcp` / `bundle-upload-azure` (off by default). When a user passes `gs://` or `https://*.blob.core.windows.net/` against a default build, `from_url` returns a `BundleUploadError::FeatureNotEnabled` with instructions to rebuild with the appropriate feature flag. The module bodies themselves contain `todo!()` constructors so a future contributor adding the impl has a clear file to fill in.

A companion subcommand, `gtc deploy refresh-bundle-url <bundle-ref>`, re-issues a fresh presigned URL and re-applies terraform without re-uploading or re-warming, addressing the operational reality that S3 SigV4 presigned URLs hard-cap at 7 days of validity.

## Motivation

The 3Point demo escalation (P0) requires a stable AWS deploy of `deep-research-demo-bundle`. Today the deploy recipe is:

1. `gtc setup deep-research-demo-bundle`
2. Warm the bundle via `greentic-start` warmup CLI (cwasm cache pre-bake; faster Fargate cold start)
3. `aws s3 cp <warmed.gtbundle> s3://<bucket>/<key>`
4. `aws s3 presign s3://<bucket>/<key> --expires-in 86400`
5. `sha256sum <warmed.gtbundle>`
6. Edit `~/.greentic/deploy/aws/<env>/<bundle>/terraform/dev.tfvars` with the URL + digest
7. `./terraform-init.sh && ./terraform-apply.sh`

Vahe needs to repeat this for every demo deploy. It is brittle (manual digest copy, presigned-URL expiry trap, no idempotency) and bottlenecks demo throughput. The bundle contains baked secrets (setup-answers with LLM/provider keys), so a public-ACL workaround is unsafe.

## Scope

### In scope
- New flag `--upload-bundle <URL>` on every `gtc` subcommand that accepts `--cloud` (search `cli.rs:241+` for the eight current sites).
- Idempotent re-run: skip upload when local digest matches the object already at the target key; only re-presign and re-apply terraform.
- Auto-warmup of the bundle before upload, by spawning `greentic-start warmup --bundle <path>` (binary-on-PATH integration; not a crate dep).
- Auto-create bucket if missing, with private + versioned + SSE-S3 defaults.
- New subcommand `gtc deploy refresh-bundle-url <bundle-ref>` for refresh-only intent (skip warmup + skip upload, just re-presign + apply).
- `BundleUploader` trait + `S3Uploader` concrete impl in `greentic-deployer/src/bundle_upload/`.
- Cargo feature flags: `bundle-upload-aws` (default-on), `bundle-upload-gcp` (off), `bundle-upload-azure` (off).
- Unit tests for URL parsing, digest computation, idempotency dispatch logic.
- Integration tests against LocalStack S3 for happy-path + bucket-auto-create paths.

### Out of scope
- Real GCS upload implementation (`GcsUploader::upload` returns `unimplemented!()`).
- Real Azure Blob upload implementation (`AzureUploader::upload` returns `unimplemented!()`).
- IAM-role-based fetch in `greentic-start` (would obviate expiry entirely; tracked as future Phase 3 work).
- CloudFront signed URL or signed-cookie fallback for arbitrary expiry.
- A built-in cron / sidecar for automatic refresh; user must wire `gtc deploy refresh-bundle-url` to their own cron.
- Public-ACL upload mode (rejected during brainstorming because demo bundles carry baked secrets).
- Multi-region replication, cross-region access, MFA delete.

### Non-goals
- Replacing `--deploy-bundle-source <URL>`; that flag remains for users who already have a remote bundle URL.
- Hosting bundles on Greentic-managed infrastructure (this is a per-user/per-tenant bucket workflow).

## Architecture

### Crate placement

All upload logic lives in `greentic-deployer/src/bundle_upload/` (Approach 1 from brainstorming). Rationale:

- `greentic-deployer` already owns cloud-specific code (`aws.rs`, `azure.rs`, `gcp.rs`); adding cloud-specific upload logic here is the natural fit.
- Reuse-first: the `BundleUploader` trait can later be consumed by `greentic-bundle wizard`, `gtc deploy`, or any future tool that produces remote bundle artifacts.
- Compile-time bloat from `aws-sdk-s3` is contained behind feature flag `bundle-upload-aws` (default-on). GCP/Azure SDKs are off by default.

### Module layout

```
greentic-deployer/src/bundle_upload/
├── mod.rs        # trait, types, dispatcher (from_url)
├── s3.rs         # S3Uploader impl (cfg(feature = "bundle-upload-aws"))
├── gcs.rs        # GcsUploader stub (cfg(feature = "bundle-upload-gcp"))
└── azure.rs      # AzureUploader stub (cfg(feature = "bundle-upload-azure"))
```

### Public API

```rust
// mod.rs
use std::path::Path;

#[derive(Debug, Clone)]
pub struct UploadedBundle {
    /// URL the operator will fetch from. Presigned for S3 (7-day max).
    pub url: String,
    /// `sha256:<hex>` of the uploaded bundle bytes.
    pub digest: String,
    /// `Some` when URL has built-in expiry (presigned). `None` for static URLs.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Cloud-native object reference, e.g. `s3://bucket/key`. Used by refresh.
    pub object_ref: String,
}

#[derive(Debug, Clone)]
pub struct UploadOptions {
    /// Presigned URL expiry in seconds. Capped at 604800 (7 days) for S3.
    pub presign_expires_secs: u64,
}

#[async_trait::async_trait]
pub trait BundleUploader: Send + Sync {
    /// Upload the bundle, computing its digest, and return a fetchable URL.
    /// Idempotent: if an object with matching digest already exists at the
    /// target key, skip the byte upload and proceed to URL issuance.
    async fn upload(
        &self,
        bundle_path: &Path,
        opts: &UploadOptions,
    ) -> Result<UploadedBundle, BundleUploadError>;

    /// Re-issue a fresh URL for an existing uploaded bundle without re-uploading.
    /// Caller passes the `object_ref` returned from a prior `upload`.
    async fn refresh_url(
        &self,
        object_ref: &str,
        opts: &UploadOptions,
    ) -> Result<UploadedBundle, BundleUploadError>;
}

/// Resolve a `BundleUploader` impl from the URL scheme of the user-supplied target.
/// `s3://bucket/prefix/`  -> S3Uploader (requires `bundle-upload-aws` feature)
/// `gs://bucket/prefix/`  -> GcsUploader (requires `bundle-upload-gcp` feature)
/// `https://*.blob.core.windows.net/...` -> AzureUploader (requires `bundle-upload-azure` feature)
pub fn from_url(url: &str) -> Result<Box<dyn BundleUploader>, BundleUploadError>;
```

### S3Uploader behavior (`s3.rs`)

**Construction**
- Parse `s3://<bucket>/<prefix>/` into `(bucket, prefix)`. Prefix may be empty or end with `/`.
- AWS credentials from default credential chain (`aws-config::load_defaults`). Region from caller's environment / profile; reject if unresolvable.

**Upload flow**
1. Compute SHA256 of the local file. Object key is deterministic: `<prefix>/<short_digest>.gtbundle` where `short_digest` is the first 16 hex chars (avoids leaking full digest in URL while staying collision-resistant for our scale).
2. `HeadBucket` on the bucket:
   - `200` → bucket exists; ensure it has SSE-S3 default encryption + versioning enabled (PutBucketEncryption / PutBucketVersioning, idempotent operations).
   - `404` → `CreateBucket` with the user's region, then enable BPA (PutPublicAccessBlock — block all four), versioning, and SSE-S3.
   - `403` → fail with policy-snippet error message (see Error Handling).
3. `HeadObject` at the target key:
   - `200` with metadata `x-amz-meta-greentic-bundle-digest` matching → skip upload.
   - `200` with mismatching metadata → overwrite (versioning protects history).
   - `404` → upload via `PutObject`, attaching metadata `x-amz-meta-greentic-bundle-digest=<full_digest>`.
4. Generate a presigned `GetObject` URL, expiry = `min(opts.presign_expires_secs, 604800)`. Return `UploadedBundle` with `object_ref = "s3://<bucket>/<key>"`.

**Refresh flow**
1. Parse `object_ref` back into `(bucket, key)`.
2. `HeadObject` to confirm existence; fail with `BundleUploadError::ObjectMissing` if gone.
3. Read `x-amz-meta-greentic-bundle-digest` to populate `digest`.
4. Generate fresh presigned URL. Return `UploadedBundle`.

### gtc CLI integration (`greentic/src/bin/gtc/`)

**New flag** added to subcommands that already accept `--cloud` (`cli.rs:241,278,313,348,392,436,480,524,577,630,676`):

```rust
.arg(
    Arg::new("upload-bundle")
        .long("upload-bundle")
        .value_name("URL")
        .num_args(1)
        .help_heading(options_heading)
        .help("Upload local bundle to cloud storage and use as --deploy-bundle-source. \
               Mutually exclusive with --deploy-bundle-source. \
               Schemes: s3://, gs://, https://*.blob.core.windows.net/")
)
.arg(
    Arg::new("upload-bundle-presign-expires")
        .long("upload-bundle-presign-expires")
        .value_name("SECONDS")
        .num_args(1)
        .default_value("604800")
        .help_heading(options_heading)
        .help("Presigned URL expiry in seconds (S3 hard-caps at 604800 = 7 days)")
)
```

**Mutual exclusivity:** if both `--upload-bundle` and `--deploy-bundle-source` are set, fail validation with a clear message. Do not silently prefer one.

**Pre-deploy hook** in `start_stop.rs` (after argument parsing, before forwarding to deployer): if `upload_bundle.is_some()`:
1. Resolve local bundle path from positional `bundle-ref` argument (must be a local path, not a remote ref).
2. Detect warmup state by inspecting bundle filename pattern and / or manifest marker (existing convention: warmed bundles include `bundle-warmed-<gs_version>-keyed-<id>.gtbundle` in `dist/`). If not warmed, spawn `greentic-start warmup --bundle <path> --output <tempdir>/warmed.gtbundle` and use the output path.
3. Construct `BundleUploader` via `bundle_upload::from_url(upload_bundle)`.
4. Call `.upload(&warmed_path, &opts)`. Synthesize `--deploy-bundle-source <result.url>` and `--bundle-digest <result.digest>` into the args vector that's forwarded to the deployer flow.
5. Print user-facing summary to stderr:
   ```
   Uploaded bundle:
     digest:      sha256:f6a487...
     url:         https://...s3.eu-north-1.amazonaws.com/...
     expires:     2026-05-14T07:18:32Z (in 7 days)
     object ref:  s3://greentic-deep-research-bundles/abc12345...
   To refresh URL without re-uploading: gtc deploy refresh-bundle-url <bundle-ref>
   ```

### Refresh subcommand (`gtc deploy refresh-bundle-url`)

**Why a top-level `gtc deploy` parent.** Today there is no `gtc deploy` subcommand; deploy operations are folded into `gtc start --cloud <X>`. As more deploy ops accumulate (refresh, status, logs, destroy), they belong under a `deploy` parent. This spec introduces `gtc deploy` with one child subcommand, leaving room for future siblings.

**Args:**
```
gtc deploy refresh-bundle-url <bundle-ref> [--cloud <provider>]
```

**Flow:**
1. Resolve the deploy state directory under `~/.greentic/deploy/<cloud>/<env>/<bundle-fingerprint>/terraform/dev.tfvars`.
   - Bundle fingerprint is the existing path-mangling scheme used by the deployer (see `terraform-handoff.txt` examples). The CLI computes the fingerprint from the user-supplied `<bundle-ref>` the same way the deploy step does.
   - If `--cloud` is omitted, the CLI scans `~/.greentic/deploy/*/<env>/<fingerprint>/`. If exactly one cloud directory matches, use it. If zero match, error with the absolute path the CLI looked for. If multiple match, error and list the candidate `--cloud` values for the user to pick.
   - `<env>` defaults to `dev` and is overridable via `--environment`.
2. Parse `dev.tfvars` to extract current `bundle_source` URL → derive `object_ref` by reverse-mapping (S3 presigned URL → `s3://<bucket>/<key>` from the `<bucket>.s3.<region>.amazonaws.com/<key>` host pattern).
3. Construct `BundleUploader` from the inferred scheme.
4. Call `.refresh_url(&object_ref, &opts)`.
5. Rewrite `dev.tfvars` with new `bundle_source`. Leave `bundle_digest` unchanged (refresh assumes content unchanged).
6. `./terraform-apply.sh` in that directory. Print expected ECS rolling-deploy ETA (`~5 minutes`).

### Warmup integration

Spawn `greentic-start warmup` as a subprocess. Rationale:

- `gtc` already requires `terraform` on PATH (`cloud_deploy.rs:62`); requiring `greentic-start` on PATH is an established pattern.
- Adding `greentic-start` as a crate dep would pull in the entire runtime dependency tree (tokio runtimes, http servers, NATS) into the `gtc` binary — significant size bloat.
- Spawn boundary makes it easy to capture warmup logs and present them as part of `gtc`'s output.

The exact subcommand shape — `greentic-start warmup --bundle <path> --output <path>` — must be verified against `greentic-start` v0.5.18+ before implementation. If the warmup CLI does not yet expose an `--output` flag, that gap is a separate ticket on `greentic-start`.

### Error handling

`BundleUploadError` enum with variants matched to recoverable user actions:

| Variant | Trigger | User-facing message |
|---|---|---|
| `InvalidUrl(String)` | scheme not recognized | "unsupported upload scheme `xyz`; expected one of: s3://, gs://, https://*.blob.core.windows.net/" |
| `FeatureNotEnabled { scheme, feature }` | scheme valid but cargo feature off | "scheme `gs://` requires building greentic-deployer with `--features bundle-upload-gcp`; current build has only `bundle-upload-aws` enabled" |
| `BucketAlreadyExistsInOtherAccount(String)` | S3 `BucketAlreadyExists` error | "bucket name `X` is taken in the global S3 namespace; pick another name (S3 bucket names are globally unique)" |
| `AccessDenied { action, resource }` | 403 from S3 API | includes minimal IAM policy snippet user must attach |
| `ObjectMissing(String)` | refresh on a key that no longer exists | "object `s3://bucket/key` not found; run upload-bundle again to recreate" |
| `WarmupFailed { stderr }` | `greentic-start warmup` non-zero exit | propagates stderr as context |
| `NetworkTransient(...)` | 5xx, timeouts | retried internally with exponential backoff (3 attempts: 1s/2s/4s); surfaces only after exhaustion |
| `CredentialsUnresolved` | default credential chain returns nothing | message points at `aws configure` / `AWS_PROFILE` env var |

No `BundleUploadError` ever bubbles up as an unstructured `anyhow::Error`; CLI layer maps each variant to a tailored user message.

### Testing

**Unit (in `greentic-deployer`)**
- `bundle_upload::from_url` table test: 8 schemes (3 valid, 5 invalid edge cases).
- `S3Uploader::object_key_for_digest` deterministic across runs.
- Idempotency dispatch: mock `S3Client` with `HeadObject` returning matching metadata → assert `PutObject` not called.
- Mutual-exclusivity validation in gtc CLI parser: unit test on the args vector.

**Integration (in `greentic-deployer/tests/`)**
- `bundle_upload_s3_localstack.rs`, gated behind `--features bundle-upload-aws` and `LOCALSTACK_ENDPOINT` env var:
  - Happy path: upload a fixture `.gtbundle`, presign, GET via reqwest, verify body matches.
  - Bucket auto-create: call upload against a non-existent bucket name, assert bucket exists with correct config (BPA, versioning, encryption).
  - Idempotent re-upload: call upload twice, second call must not increment object version count.
  - Refresh: call refresh on a known object, validate URL changes but key unchanged.
- LocalStack runs in CI via `services:` in the workflow; deferred work documents how to enable.

**Manual verification**
- Bima runs end-to-end against the real `greentic-deep-research-local-20260430-vahe` bucket against the deep-research-demo-bundle and confirms 3Point demo deploy completes from a single command.
- Vahe reproduces the same against a bucket he creates fresh (validates auto-create).

### Backward compatibility

- Existing `--deploy-bundle-source <URL>` behavior unchanged. Users who have a pre-published OCI / repo / store bundle URL keep using it.
- New `gtc deploy` parent subcommand is brand-new; no clash with existing commands (`start`, `stop`, `setup`, `wizard`, `dev`, `op`, etc.).
- The `bundle-upload-aws` cargo feature is on by default; existing build-and-test of `greentic-deployer` continues to compile. Downstream consumers (`gtc`, `greentic-deployer-extensions`) get the feature transitively unless they explicitly disable it.

### Telemetry / observability

No new telemetry is added. Upload outcomes are surfaced inline to stderr; existing deploy telemetry already covers the post-upload terraform stages.

## Migration / rollout plan

**Phase 1 (this PR — target main):** trait + S3 impl + flag wiring + refresh subcommand + tests + docs. Vahe / Bima validate against deep-research-demo-bundle for 3Point.

**Phase 2 (separate, when first non-AWS demo lands):** GCS impl, then Azure Blob impl. Each behind its feature flag.

**Phase 3 (separate, future):** add `s3://` / `gs://` / `azure-blob://` scheme support to `greentic-start/src/bundle_ref.rs` so the operator fetches with IAM role / workload identity, eliminating presigned-URL expiry as an operational concern. At that point `gtc deploy refresh-bundle-url` becomes vestigial and can be deprecated.

## Open implementation decisions

- **Subcommand placement:** `gtc deploy refresh-bundle-url` (this spec) vs `gtc start refresh-bundle-url`. This spec picks `gtc deploy` to anchor a future ops domain. If reviewers prefer keeping all deploy ops inside `gtc start`, change is local to `cli.rs` argument tree.
- **Warmup CLI shape verification:** confirm `greentic-start warmup --bundle <path> --output <path>` exists and accepts those flags in 0.5.18+. If `--output` does not exist, file a `greentic-start` ticket as a precondition.
- **Bucket auto-create region default:** if no region available from AWS profile + no `--region` flag, error out vs default to `us-east-1`. This spec recommends erroring out (no surprise region).

## References

- Brainstorming session log: this conversation
- 3Point demo escalation: project memory `project_3point_escalation.md`
- Operator image pinning context: project memory `project_warmup_autoadopt_fargate_bug.md`
- Existing AWS deploy code: `greentic-deployer/src/aws.rs`, `greentic-deployer/src/apply.rs`
- Existing CLI surface: `greentic/src/bin/gtc/cli.rs`, `greentic/src/bin/gtc/deploy/cloud_deploy.rs`
- Earlier deployer design docs: `docs/superpowers/specs/2026-04-19-phase-b-4b-4c-aws-ecs-fargate-design.md`
