//! Derive [`BinaryArtifact`](greentic_update::plan::BinaryArtifact)s from a
//! GitHub release's archive assets.
//!
//! For each target archive in the release, downloads the archive and its
//! `.sha256` sidecar, verifies the archive against the sidecar, unpacks the
//! inner binary via [`greentic_update::binswap::unpack_release_binary`],
//! sha256s the inner binary, and emits a `BinaryArtifact` with the archive's
//! `browser_download_url` as the `source`.

use std::collections::HashMap;
use std::io::Read;

use super::OpError;
use greentic_update::plan::BinaryArtifact;
use serde::Deserialize;

/// Mirror the consumer's download cap (256 MiB, from greentic-start).
const MAX_BINARY_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum sidecar size (1 KiB; a sha256 sidecar is ~120 bytes).
const MAX_SIDECAR_BYTES: u64 = 1024;

/// Download timeout mirroring the consumer (300s, from greentic-start).
const BINARY_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Total download attempts per asset before giving up (1 initial + 3 retries).
///
/// A coordinated publish derives ~168 assets (6 archives + 6 sidecars across 14
/// packages), so it is exposed to any intermittent failure on GitHub's release
/// CDN: a single 5xx anywhere in that sweep aborts the whole publish. Observed
/// in production as repeated `504 Gateway Timeout` on `.sha256` sidecars whose
/// URLs returned 200 seconds later by hand.
const FETCH_MAX_ATTEMPTS: u32 = 4;

/// Base delay for the exponential backoff between download attempts.
const FETCH_BACKOFF_BASE: std::time::Duration = std::time::Duration::from_millis(500);

/// Windows target triples that produce `.exe` inner binaries.
fn is_windows_target(target: &str) -> bool {
    target.contains("-windows-")
}

/// What to derive binary artifacts from.
#[derive(Clone, Debug)]
pub struct ReleaseSpec {
    pub owner: String,
    pub repo: String,
    pub binary_name: String,
    pub version: String,
    pub tag: String,
    /// When non-empty, only derive artifacts for these target triples.
    pub targets: Vec<String>,
    /// When set and `targets` is empty (discover-all mode), the discovered
    /// archive count must equal this value. Guards against partial releases
    /// silently producing fewer artifacts than expected.
    pub expected_target_count: Option<usize>,
    /// Override the default `{binary_name}-v{version}-` archive-name prefix.
    /// Used by repos whose release assets do not follow the standard naming
    /// (e.g. `gtc` ships archives as `gtc-{target}.tgz`, so prefix = `"gtc-"`).
    pub archive_prefix: Option<String>,
    /// Name of a consolidated checksums asset (sha256sum-format) attached to
    /// the GitHub release. When set, per-archive `.sha256` sidecars are not
    /// required; digests are looked up in this single file instead.
    pub checksums_asset: Option<String>,
}

/// A single asset from the GitHub Releases API.
#[derive(Clone, Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

/// Subset of the GitHub release response.
#[derive(Debug, Deserialize)]
struct GitHubRelease {
    assets: Vec<GitHubAsset>,
}

/// Build a reqwest blocking client with GitHub auth + UA + timeout.
fn github_client() -> Result<reqwest::blocking::Client, OpError> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::USER_AGENT,
        reqwest::header::HeaderValue::from_static(concat!(
            "greentic-deployer/",
            env!("CARGO_PKG_VERSION")
        )),
    );
    if let Ok(token) = std::env::var("GITHUB_TOKEN").or_else(|_| std::env::var("GH_TOKEN")) {
        let token = token.trim().to_string();
        if !token.is_empty() {
            headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")).map_err(
                    |e| OpError::InvalidArgument(format!("invalid GitHub token header: {e}")),
                )?,
            );
        }
    }
    reqwest::blocking::Client::builder()
        .default_headers(headers)
        .timeout(BINARY_FETCH_TIMEOUT)
        .build()
        .map_err(|e| OpError::Fetch(format!("building GitHub client: {e}")))
}

/// Is this HTTP status worth retrying?
///
/// Server errors and rate limiting are the transient shapes GitHub's release
/// CDN produces under a bulk sweep. `401`/`403`/`404` are deliberately absent:
/// they are deterministic answers about the token or the asset, and retrying
/// them only delays an honest failure by the whole backoff budget.
fn status_is_transient(status: reqwest::StatusCode) -> bool {
    status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS
}

/// Is this transport error worth retrying? Timeouts, connect failures and
/// truncated bodies are all "try again"; a malformed URL is not.
fn transport_error_is_transient(err: &reqwest::Error) -> bool {
    err.is_timeout() || err.is_connect() || err.is_body() || err.is_decode()
}

/// Backoff before attempt `attempt` (1-based): 0.5s, 1s, 2s, ...
fn backoff_for_attempt(attempt: u32) -> std::time::Duration {
    FETCH_BACKOFF_BASE * 2u32.pow(attempt.saturating_sub(1))
}

/// A failed download attempt, tagged with whether retrying could help.
enum AttemptError {
    Transient(OpError),
    Permanent(OpError),
}

impl AttemptError {
    fn into_inner(self) -> OpError {
        match self {
            AttemptError::Transient(e) | AttemptError::Permanent(e) => e,
        }
    }
}

/// Download bytes from `url` with a size cap, retrying transient failures with
/// exponential backoff. Permanent failures (auth, missing asset, oversized
/// body) return immediately.
fn download_capped(
    client: &reqwest::blocking::Client,
    url: &str,
    cap: u64,
) -> Result<Vec<u8>, OpError> {
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match download_capped_once(client, url, cap) {
            Ok(bytes) => return Ok(bytes),
            Err(AttemptError::Transient(e)) if attempt < FETCH_MAX_ATTEMPTS => {
                let delay = backoff_for_attempt(attempt);
                eprintln!(
                    "warning: transient fetch failure (attempt {attempt}/{FETCH_MAX_ATTEMPTS}), \
                     retrying in {:?}: {e}",
                    delay
                );
                std::thread::sleep(delay);
            }
            Err(other) => return Err(other.into_inner()),
        }
    }
}

/// One download attempt. Classifies its failure so the caller can decide
/// whether to retry.
fn download_capped_once(
    client: &reqwest::blocking::Client,
    url: &str,
    cap: u64,
) -> Result<Vec<u8>, AttemptError> {
    let resp = client.get(url).send().map_err(|e| {
        let err = OpError::Fetch(format!("GET {url}: {e}"));
        if transport_error_is_transient(&e) {
            AttemptError::Transient(err)
        } else {
            AttemptError::Permanent(err)
        }
    })?;
    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(AttemptError::Permanent(OpError::Unauthorized {
            policy: "github-release".to_string(),
            reason: format!("GitHub API returned {status} for {url}"),
        }));
    }
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(AttemptError::Permanent(OpError::NotFound(format!(
            "asset not found: {url}"
        ))));
    }
    if status_is_transient(status) {
        return Err(AttemptError::Transient(OpError::Fetch(format!(
            "GET {url}: HTTP status {status}"
        ))));
    }
    let resp = resp
        .error_for_status()
        .map_err(|e| AttemptError::Permanent(OpError::Fetch(format!("GET {url}: {e}"))))?;

    let mut buf = Vec::new();
    // A truncated body is a transport hiccup, not a bad asset — retry it.
    resp.take(cap + 1)
        .read_to_end(&mut buf)
        .map_err(|e| AttemptError::Transient(OpError::Fetch(format!("reading {url}: {e}"))))?;
    if buf.len() as u64 > cap {
        return Err(AttemptError::Permanent(OpError::InvalidArgument(format!(
            "asset {url} exceeds {cap} byte cap"
        ))));
    }
    Ok(buf)
}

/// Parse a `.sha256` sidecar file. Format: `<hex>  <filename>\n` or `<hex>
/// <filename>\n` (BSD/GNU sha256sum output). Rejects multi-line sidecars
/// (batch `sha256sum *.tgz` output) to prevent silent first-line extraction.
pub(crate) fn parse_sidecar_digest(sidecar: &str) -> Result<String, OpError> {
    let trimmed = sidecar.trim();
    if trimmed.is_empty() {
        return Err(OpError::InvalidArgument(
            "sha256 sidecar is empty".to_string(),
        ));
    }
    // Reject multi-line sidecars: each archive must have its own sidecar file.
    let non_empty_line_count = trimmed.lines().filter(|l| !l.trim().is_empty()).count();
    if non_empty_line_count > 1 {
        return Err(OpError::InvalidArgument(format!(
            "sha256 sidecar contains {non_empty_line_count} lines; expected exactly one \
             (each archive needs its own .sha256 sidecar)",
        )));
    }
    // Split on whitespace: first token is the hex digest.
    let hex_digest = trimmed
        .split_whitespace()
        .next()
        .ok_or_else(|| OpError::InvalidArgument("sha256 sidecar has no digest field".to_string()))?
        .to_ascii_lowercase();
    if hex_digest.len() != 64 || !hex_digest.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(OpError::InvalidArgument(format!(
            "sha256 sidecar digest is not 64 hex chars: `{hex_digest}`"
        )));
    }
    Ok(hex_digest)
}

/// Parse a consolidated checksums file (sha256sum batch output). Format:
/// `<hex>  <filename>\n` per line. Returns a map from filename to lowercase
/// hex digest. Rejects empty files and lines with malformed digests.
pub(crate) fn parse_consolidated_checksums(text: &str) -> Result<HashMap<String, String>, OpError> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(OpError::InvalidArgument(
            "consolidated checksums file is empty".to_string(),
        ));
    }
    let mut map = HashMap::new();
    for (i, line) in trimmed.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, |c: char| c.is_ascii_whitespace());
        let hex_digest = parts
            .next()
            .ok_or_else(|| {
                OpError::InvalidArgument(format!("checksums line {}: no digest field", i + 1))
            })?
            .to_ascii_lowercase();
        if hex_digest.len() != 64 || !hex_digest.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(OpError::InvalidArgument(format!(
                "checksums line {}: digest is not 64 hex chars: `{hex_digest}`",
                i + 1
            )));
        }
        let filename = parts
            .next()
            .map(|s| s.trim_start())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                OpError::InvalidArgument(format!(
                    "checksums line {}: missing filename after digest",
                    i + 1
                ))
            })?
            .to_string();
        map.insert(filename, hex_digest);
    }
    if map.is_empty() {
        return Err(OpError::InvalidArgument(
            "consolidated checksums file contains no valid entries".to_string(),
        ));
    }
    Ok(map)
}

/// Maximum consolidated checksums file size (64 KiB; typically ~1 KiB).
const MAX_CHECKSUMS_BYTES: u64 = 64 * 1024;

/// Derive `BinaryArtifact`s from a GitHub release.
///
/// Fail-closed: any missing asset, unparseable sidecar, digest mismatch, or
/// unpack failure fails the whole command. Use `spec.targets` to narrow
/// which triples are derived (the escape hatch for partial releases).
/// When `spec.targets` is empty and `spec.expected_target_count` is set,
/// the discovered archive count must match the expected count.
pub fn derive_binary_artifacts(spec: &ReleaseSpec) -> Result<Vec<BinaryArtifact>, OpError> {
    let client = github_client()?;
    let checksums_asset_name = spec.checksums_asset.clone();
    let fetcher = move |url: &str| -> Result<Vec<u8>, OpError> {
        let cap = if url.contains("/releases/tags/") {
            MAX_SIDECAR_BYTES * 1024
        } else if url.ends_with(".sha256") {
            MAX_SIDECAR_BYTES
        } else if checksums_asset_name
            .as_ref()
            .is_some_and(|name| url.ends_with(name))
        {
            MAX_CHECKSUMS_BYTES
        } else {
            MAX_BINARY_ARCHIVE_BYTES
        };
        download_capped(&client, url, cap)
    };
    derive_binary_artifacts_inner(spec, &fetcher)
}

/// Shared implementation: derive artifacts using a provided fetcher function.
/// Both the production entry point and tests delegate here.
fn derive_binary_artifacts_inner<F>(
    spec: &ReleaseSpec,
    fetcher: &F,
) -> Result<Vec<BinaryArtifact>, OpError>
where
    F: Fn(&str) -> Result<Vec<u8>, OpError>,
{
    // Fetch release metadata.
    let release_url = format!(
        "https://api.github.com/repos/{}/{}/releases/tags/{}",
        spec.owner, spec.repo, spec.tag
    );
    let release_bytes = fetcher(&release_url)?;
    let release: GitHubRelease = serde_json::from_slice(&release_bytes)
        .map_err(|e| OpError::InvalidArgument(format!("GitHub release JSON parse error: {e}")))?;

    let assets_by_name: HashMap<&str, &GitHubAsset> = release
        .assets
        .iter()
        .map(|a| (a.name.as_str(), a))
        .collect();

    let prefix = match &spec.archive_prefix {
        Some(p) => p.clone(),
        None => format!("{}-v{}-", spec.binary_name, spec.version),
    };
    let archive_assets: Vec<(&GitHubAsset, String)> = release
        .assets
        .iter()
        .filter_map(|asset| {
            let name = &asset.name;
            if !name.starts_with(&prefix) {
                return None;
            }
            let suffix = &name[prefix.len()..];
            let target = suffix
                .strip_suffix(".tgz")
                .or_else(|| suffix.strip_suffix(".tar.gz"))
                .or_else(|| suffix.strip_suffix(".zip"))?;
            if target.ends_with(".sha256")
                || target.ends_with(".tgz")
                || target.ends_with(".tar.gz")
                || target.ends_with(".zip")
            {
                return None;
            }
            Some((asset, target.to_string()))
        })
        .collect();

    if archive_assets.is_empty() {
        return Err(OpError::InvalidArgument(format!(
            "release {} has no archive assets matching `{prefix}*`",
            spec.tag
        )));
    }

    let filtered: Vec<(&GitHubAsset, String)> = if spec.targets.is_empty() {
        // Discover-all mode: validate expected count if set.
        if let Some(expected) = spec.expected_target_count
            && archive_assets.len() != expected
        {
            let discovered: Vec<&str> = archive_assets.iter().map(|(_, t)| t.as_str()).collect();
            return Err(OpError::InvalidArgument(format!(
                "expected {expected} target archives in release {}, found {}: [{}]. \
                 Use --targets to list the expected set, or fix the release.",
                spec.tag,
                archive_assets.len(),
                discovered.join(", "),
            )));
        }
        archive_assets
    } else {
        let requested: std::collections::HashSet<&str> =
            spec.targets.iter().map(String::as_str).collect();
        let filtered: Vec<_> = archive_assets
            .into_iter()
            .filter(|(_, target)| requested.contains(target.as_str()))
            .collect();
        for t in &spec.targets {
            if !filtered.iter().any(|(_, target)| target == t) {
                return Err(OpError::NotFound(format!(
                    "release {} has no archive for target `{t}`",
                    spec.tag
                )));
            }
        }
        filtered
    };

    // Reject duplicate target triples (e.g. both .tgz and .zip for the same
    // target). The downstream consumer rejects ambiguous (name, target) pairs,
    // so producing them here would create plans that always fail on apply.
    {
        let mut seen = std::collections::HashSet::with_capacity(filtered.len());
        for (_, target) in &filtered {
            if !seen.insert(target.as_str()) {
                return Err(OpError::InvalidArgument(format!(
                    "release {} has duplicate archives for target `{target}` \
                     (e.g. both .tgz and .zip); remove the extra archive or use \
                     --targets to select one format",
                    spec.tag,
                )));
            }
        }
    }

    // When a consolidated checksums asset is configured, fetch and parse it
    // once up front instead of fetching per-archive .sha256 sidecars.
    let consolidated_digests: Option<HashMap<String, String>> =
        if let Some(checksums_name) = &spec.checksums_asset {
            let checksums_asset = assets_by_name.get(checksums_name.as_str()).ok_or_else(|| {
                OpError::NotFound(format!(
                    "release {} is missing checksums asset `{checksums_name}`",
                    spec.tag
                ))
            })?;
            let checksums_bytes = fetcher(&checksums_asset.browser_download_url)?;
            let checksums_text = String::from_utf8(checksums_bytes).map_err(|e| {
                OpError::InvalidArgument(format!(
                    "checksums asset `{checksums_name}` is not UTF-8: {e}"
                ))
            })?;
            Some(parse_consolidated_checksums(&checksums_text)?)
        } else {
            None
        };

    let tmp_dir = tempfile::tempdir().map_err(|e| OpError::Fetch(format!("tempdir: {e}")))?;
    let mut artifacts = Vec::with_capacity(filtered.len());

    for (archive_asset, target) in &filtered {
        let expected_archive_digest = if let Some(ref digests) = consolidated_digests {
            // Consolidated checksums path: look up by archive filename.
            digests.get(&archive_asset.name).cloned().ok_or_else(|| {
                OpError::NotFound(format!(
                    "consolidated checksums for release {} has no entry for `{}`",
                    spec.tag, archive_asset.name
                ))
            })?
        } else {
            // Per-archive sidecar path (existing behavior).
            let sidecar_name = format!("{}.sha256", archive_asset.name);
            let sidecar_asset = assets_by_name.get(sidecar_name.as_str()).ok_or_else(|| {
                OpError::NotFound(format!(
                    "release {} is missing sidecar `{sidecar_name}`",
                    spec.tag
                ))
            })?;
            let sidecar_bytes = fetcher(&sidecar_asset.browser_download_url)?;
            let sidecar_text = String::from_utf8(sidecar_bytes).map_err(|e| {
                OpError::InvalidArgument(format!("sidecar `{sidecar_name}` is not UTF-8: {e}"))
            })?;
            parse_sidecar_digest(&sidecar_text)?
        };

        let archive_bytes = fetcher(&archive_asset.browser_download_url)?;

        let actual_archive_digest = greentic_update::plan::sha256_hex(&archive_bytes);
        if actual_archive_digest != expected_archive_digest {
            return Err(OpError::Conflict(format!(
                "archive sha256 mismatch for {target}: expected {expected_archive_digest}, got {actual_archive_digest}"
            )));
        }

        let archive_ext = if archive_asset.name.ends_with(".zip") {
            "zip"
        } else {
            "tgz"
        };
        let archive_path = tmp_dir.path().join(format!("{target}.{archive_ext}"));
        std::fs::write(&archive_path, &archive_bytes).map_err(|source| OpError::Io {
            path: archive_path.clone(),
            source,
        })?;

        let unpack_dir = tmp_dir.path().join(format!("{target}-unpack"));
        std::fs::create_dir_all(&unpack_dir).map_err(|source| OpError::Io {
            path: unpack_dir.clone(),
            source,
        })?;

        let inner_binary_name = if is_windows_target(target) {
            format!("{}.exe", spec.binary_name)
        } else {
            spec.binary_name.clone()
        };

        let inner_path = greentic_update::binswap::unpack_release_binary(
            &archive_path,
            &inner_binary_name,
            &unpack_dir,
        )
        .map_err(|e| {
            OpError::InvalidArgument(format!(
                "unpacking inner binary `{inner_binary_name}` from {target} archive: {e}"
            ))
        })?;

        let inner_bytes = std::fs::read(&inner_path).map_err(|source| OpError::Io {
            path: inner_path.clone(),
            source,
        })?;
        let inner_digest = format!("sha256:{}", greentic_update::plan::sha256_hex(&inner_bytes));

        artifacts.push(BinaryArtifact {
            name: spec.binary_name.clone(),
            version: spec.version.clone(),
            target: target.clone(),
            digest: inner_digest,
            source: Some(archive_asset.browser_download_url.clone()),
        });
    }

    Ok(artifacts)
}

/// Test-visible alias that delegates to the shared inner function.
#[cfg(test)]
pub(crate) fn derive_binary_artifacts_with_fetcher<F>(
    spec: &ReleaseSpec,
    fetcher: &F,
) -> Result<Vec<BinaryArtifact>, OpError>
where
    F: Fn(&str) -> Result<Vec<u8>, OpError>,
{
    derive_binary_artifacts_inner(spec, fetcher)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build a tar.gz archive containing a single binary at
    /// `{dir_name}/{binary_name}` with the given content.
    fn build_tgz(dir_name: &str, binary_name: &str, content: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        let entry_path = format!("{dir_name}/{binary_name}");
        builder
            .append_data(&mut header, &entry_path, content)
            .unwrap();
        let tar_bytes = builder.into_inner().unwrap();
        let mut gz_buf = Vec::new();
        let mut encoder =
            flate2::write::GzEncoder::new(&mut gz_buf, flate2::Compression::default());
        encoder.write_all(&tar_bytes).unwrap();
        encoder.finish().unwrap();
        gz_buf
    }

    /// Build a zip archive containing a single binary at
    /// `{dir_name}/{binary_name}` with the given content.
    fn build_zip_archive(dir_name: &str, binary_name: &str, content: &[u8]) -> Vec<u8> {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut buf);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            let entry_path = format!("{dir_name}/{binary_name}");
            writer.start_file(&entry_path, options).unwrap();
            writer.write_all(content).unwrap();
            writer.finish().unwrap();
        }
        buf.into_inner()
    }

    fn sha256_hex(data: &[u8]) -> String {
        greentic_update::plan::sha256_hex(data)
    }

    fn make_sidecar(archive_bytes: &[u8], filename: &str) -> String {
        format!("{}  {}\n", sha256_hex(archive_bytes), filename)
    }

    /// Build a fake GitHub release JSON with the given assets.
    fn release_json(assets: &[(&str, &str)]) -> Vec<u8> {
        let asset_list: Vec<serde_json::Value> = assets
            .iter()
            .map(|(name, url)| {
                serde_json::json!({
                    "name": name,
                    "browser_download_url": url,
                })
            })
            .collect();
        serde_json::to_vec(&serde_json::json!({ "assets": asset_list })).unwrap()
    }

    // --- fetch retry classification ------------------------------------------

    #[test]
    fn server_errors_and_rate_limit_are_transient() {
        for code in [500u16, 502, 503, 504, 429] {
            let status = reqwest::StatusCode::from_u16(code).unwrap();
            assert!(
                status_is_transient(status),
                "{code} should be retried — it is how the release CDN fails under a bulk sweep"
            );
        }
    }

    #[test]
    fn deterministic_statuses_are_not_retried() {
        // Retrying these only delays an honest failure by the whole backoff
        // budget: they are answers about the token or the asset, not weather.
        for code in [400u16, 401, 403, 404, 410, 422] {
            let status = reqwest::StatusCode::from_u16(code).unwrap();
            assert!(!status_is_transient(status), "{code} must not be retried");
        }
    }

    #[test]
    fn success_status_is_not_transient() {
        assert!(!status_is_transient(reqwest::StatusCode::OK));
        assert!(!status_is_transient(reqwest::StatusCode::PARTIAL_CONTENT));
    }

    #[test]
    fn backoff_grows_exponentially_from_the_base() {
        assert_eq!(backoff_for_attempt(1), FETCH_BACKOFF_BASE);
        assert_eq!(backoff_for_attempt(2), FETCH_BACKOFF_BASE * 2);
        assert_eq!(backoff_for_attempt(3), FETCH_BACKOFF_BASE * 4);
    }

    #[test]
    fn total_backoff_stays_within_a_sane_budget() {
        // 4 attempts => sleeps before attempts 2, 3, 4 only.
        let total: std::time::Duration = (1..FETCH_MAX_ATTEMPTS).map(backoff_for_attempt).sum();
        assert_eq!(total, std::time::Duration::from_millis(3500));
    }

    #[test]
    fn attempt_error_preserves_the_underlying_error() {
        let transient = AttemptError::Transient(OpError::Fetch("boom".to_string()));
        assert!(matches!(transient.into_inner(), OpError::Fetch(m) if m == "boom"));
        let permanent = AttemptError::Permanent(OpError::NotFound("gone".to_string()));
        assert!(matches!(permanent.into_inner(), OpError::NotFound(m) if m == "gone"));
    }

    // --- parse_sidecar_digest ------------------------------------------------

    #[test]
    fn sidecar_happy_path() {
        let digest = parse_sidecar_digest(
            "9d690509207168dc283092be4dd64a377e88d4a9744dfcbb8abf5ddee576bf98  archive.tgz\n",
        )
        .unwrap();
        assert_eq!(
            digest,
            "9d690509207168dc283092be4dd64a377e88d4a9744dfcbb8abf5ddee576bf98"
        );
    }

    #[test]
    fn sidecar_no_trailing_newline() {
        let digest = parse_sidecar_digest(
            "9d690509207168dc283092be4dd64a377e88d4a9744dfcbb8abf5ddee576bf98  archive.tgz",
        )
        .unwrap();
        assert_eq!(
            digest,
            "9d690509207168dc283092be4dd64a377e88d4a9744dfcbb8abf5ddee576bf98"
        );
    }

    #[test]
    fn sidecar_extra_whitespace() {
        let digest = parse_sidecar_digest(
            "  9d690509207168dc283092be4dd64a377e88d4a9744dfcbb8abf5ddee576bf98   archive.tgz  \n",
        )
        .unwrap();
        assert_eq!(
            digest,
            "9d690509207168dc283092be4dd64a377e88d4a9744dfcbb8abf5ddee576bf98"
        );
    }

    #[test]
    fn sidecar_empty() {
        let err = parse_sidecar_digest("").unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    #[test]
    fn sidecar_short_hex() {
        let err = parse_sidecar_digest("abcd1234  archive.tgz").unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(ref m) if m.contains("64 hex")));
    }

    #[test]
    fn sidecar_garbage_hex() {
        let err = parse_sidecar_digest(
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz  a.tgz",
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(ref m) if m.contains("64 hex")));
    }

    #[test]
    fn sidecar_no_separator() {
        // 64 hex chars with no filename -- still parses (the digest is the first
        // whitespace-delimited token).
        let digest = parse_sidecar_digest(
            "9d690509207168dc283092be4dd64a377e88d4a9744dfcbb8abf5ddee576bf98",
        )
        .unwrap();
        assert_eq!(
            digest,
            "9d690509207168dc283092be4dd64a377e88d4a9744dfcbb8abf5ddee576bf98"
        );
    }

    // --- derive_binary_artifacts (via test fetcher) --------------------------

    #[test]
    fn derive_tgz_happy_path() {
        let binary_content = b"fake-binary-content-for-hashing";
        let inner_digest = format!("sha256:{}", sha256_hex(binary_content));

        let tgz = build_tgz(
            "mybin-v1.0.0-x86_64-unknown-linux-gnu",
            "mybin",
            binary_content,
        );
        let sidecar = make_sidecar(&tgz, "mybin-v1.0.0-x86_64-unknown-linux-gnu.tgz");

        let release = release_json(&[
            (
                "mybin-v1.0.0-x86_64-unknown-linux-gnu.tgz",
                "https://example.com/mybin-v1.0.0-x86_64-unknown-linux-gnu.tgz",
            ),
            (
                "mybin-v1.0.0-x86_64-unknown-linux-gnu.tgz.sha256",
                "https://example.com/mybin-v1.0.0-x86_64-unknown-linux-gnu.tgz.sha256",
            ),
        ]);

        let spec = ReleaseSpec {
            owner: "test".to_string(),
            repo: "test".to_string(),
            binary_name: "mybin".to_string(),
            version: "1.0.0".to_string(),
            tag: "v1.0.0".to_string(),
            targets: vec![],
            expected_target_count: None,
            archive_prefix: None,
            checksums_asset: None,
        };

        let fetcher = move |url: &str| -> Result<Vec<u8>, OpError> {
            if url.contains("/releases/tags/") {
                Ok(release.clone())
            } else if url.ends_with(".sha256") {
                Ok(sidecar.as_bytes().to_vec())
            } else if url.ends_with(".tgz") {
                Ok(tgz.clone())
            } else {
                Err(OpError::NotFound(format!("unexpected URL: {url}")))
            }
        };

        let artifacts = derive_binary_artifacts_with_fetcher(&spec, &fetcher).unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].name, "mybin");
        assert_eq!(artifacts[0].version, "1.0.0");
        assert_eq!(artifacts[0].target, "x86_64-unknown-linux-gnu");
        assert_eq!(artifacts[0].digest, inner_digest);
        assert_eq!(
            artifacts[0].source.as_deref(),
            Some("https://example.com/mybin-v1.0.0-x86_64-unknown-linux-gnu.tgz")
        );
    }

    #[test]
    fn derive_zip_windows_exe() {
        let binary_content = b"fake-windows-exe";
        let inner_digest = format!("sha256:{}", sha256_hex(binary_content));

        let zip_bytes = build_zip_archive(
            "mybin-v1.0.0-x86_64-pc-windows-msvc",
            "mybin.exe",
            binary_content,
        );
        let sidecar = make_sidecar(&zip_bytes, "mybin-v1.0.0-x86_64-pc-windows-msvc.zip");

        let release = release_json(&[
            (
                "mybin-v1.0.0-x86_64-pc-windows-msvc.zip",
                "https://example.com/mybin-v1.0.0-x86_64-pc-windows-msvc.zip",
            ),
            (
                "mybin-v1.0.0-x86_64-pc-windows-msvc.zip.sha256",
                "https://example.com/mybin-v1.0.0-x86_64-pc-windows-msvc.zip.sha256",
            ),
        ]);

        let spec = ReleaseSpec {
            owner: "test".to_string(),
            repo: "test".to_string(),
            binary_name: "mybin".to_string(),
            version: "1.0.0".to_string(),
            tag: "v1.0.0".to_string(),
            targets: vec![],
            expected_target_count: None,
            archive_prefix: None,
            checksums_asset: None,
        };

        let fetcher = move |url: &str| -> Result<Vec<u8>, OpError> {
            if url.contains("/releases/tags/") {
                Ok(release.clone())
            } else if url.ends_with(".sha256") {
                Ok(sidecar.as_bytes().to_vec())
            } else if url.ends_with(".zip") {
                Ok(zip_bytes.clone())
            } else {
                Err(OpError::NotFound(format!("unexpected URL: {url}")))
            }
        };

        let artifacts = derive_binary_artifacts_with_fetcher(&spec, &fetcher).unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].target, "x86_64-pc-windows-msvc");
        assert_eq!(artifacts[0].digest, inner_digest);
    }

    #[test]
    fn archive_digest_mismatch_fails() {
        let binary_content = b"binary";
        let tgz = build_tgz("b-v1.0.0-x86_64-unknown-linux-gnu", "b", binary_content);
        // Wrong sidecar digest.
        let sidecar = format!(
            "{}  b-v1.0.0-x86_64-unknown-linux-gnu.tgz\n",
            "0000000000000000000000000000000000000000000000000000000000000000"
        );

        let release = release_json(&[
            (
                "b-v1.0.0-x86_64-unknown-linux-gnu.tgz",
                "https://example.com/b.tgz",
            ),
            (
                "b-v1.0.0-x86_64-unknown-linux-gnu.tgz.sha256",
                "https://example.com/b.tgz.sha256",
            ),
        ]);

        let spec = ReleaseSpec {
            owner: "t".to_string(),
            repo: "t".to_string(),
            binary_name: "b".to_string(),
            version: "1.0.0".to_string(),
            tag: "v1.0.0".to_string(),
            targets: vec![],
            expected_target_count: None,
            archive_prefix: None,
            checksums_asset: None,
        };

        let fetcher = move |url: &str| -> Result<Vec<u8>, OpError> {
            if url.contains("/releases/tags/") {
                Ok(release.clone())
            } else if url.ends_with(".sha256") {
                Ok(sidecar.as_bytes().to_vec())
            } else {
                Ok(tgz.clone())
            }
        };

        let err = derive_binary_artifacts_with_fetcher(&spec, &fetcher).unwrap_err();
        assert!(
            matches!(&err, OpError::Conflict(m) if m.contains("sha256 mismatch")),
            "expected digest mismatch error, got: {err:?}"
        );
    }

    #[test]
    fn missing_requested_target_fails() {
        let release = release_json(&[(
            "b-v1.0.0-x86_64-unknown-linux-gnu.tgz",
            "https://example.com/b.tgz",
        )]);

        let spec = ReleaseSpec {
            owner: "t".to_string(),
            repo: "t".to_string(),
            binary_name: "b".to_string(),
            version: "1.0.0".to_string(),
            tag: "v1.0.0".to_string(),
            targets: vec!["aarch64-apple-darwin".to_string()],
            expected_target_count: None,
            archive_prefix: None,
            checksums_asset: None,
        };

        let fetcher = move |url: &str| -> Result<Vec<u8>, OpError> {
            if url.contains("/releases/tags/") {
                Ok(release.clone())
            } else {
                Err(OpError::NotFound(url.to_string()))
            }
        };

        let err = derive_binary_artifacts_with_fetcher(&spec, &fetcher).unwrap_err();
        assert!(
            matches!(&err, OpError::NotFound(m) if m.contains("aarch64-apple-darwin")),
            "expected NotFound for missing target, got: {err:?}"
        );
    }

    #[test]
    fn targets_filter_narrows_correctly() {
        let content_linux = b"linux-bin";
        let content_mac = b"mac-bin";
        let tgz_linux = build_tgz("b-v1.0.0-x86_64-unknown-linux-gnu", "b", content_linux);
        let tgz_mac = build_tgz("b-v1.0.0-aarch64-apple-darwin", "b", content_mac);
        let sidecar_linux = make_sidecar(&tgz_linux, "b-v1.0.0-x86_64-unknown-linux-gnu.tgz");
        let sidecar_mac = make_sidecar(&tgz_mac, "b-v1.0.0-aarch64-apple-darwin.tgz");

        let release = release_json(&[
            (
                "b-v1.0.0-x86_64-unknown-linux-gnu.tgz",
                "https://e.com/linux.tgz",
            ),
            (
                "b-v1.0.0-x86_64-unknown-linux-gnu.tgz.sha256",
                "https://e.com/linux.tgz.sha256",
            ),
            ("b-v1.0.0-aarch64-apple-darwin.tgz", "https://e.com/mac.tgz"),
            (
                "b-v1.0.0-aarch64-apple-darwin.tgz.sha256",
                "https://e.com/mac.tgz.sha256",
            ),
        ]);

        let spec = ReleaseSpec {
            owner: "t".to_string(),
            repo: "t".to_string(),
            binary_name: "b".to_string(),
            version: "1.0.0".to_string(),
            tag: "v1.0.0".to_string(),
            targets: vec!["x86_64-unknown-linux-gnu".to_string()],
            expected_target_count: None,
            archive_prefix: None,
            checksums_asset: None,
        };

        let fetcher = move |url: &str| -> Result<Vec<u8>, OpError> {
            if url.contains("/releases/tags/") {
                Ok(release.clone())
            } else if url == "https://e.com/linux.tgz.sha256" {
                Ok(sidecar_linux.as_bytes().to_vec())
            } else if url == "https://e.com/mac.tgz.sha256" {
                Ok(sidecar_mac.as_bytes().to_vec())
            } else if url == "https://e.com/linux.tgz" {
                Ok(tgz_linux.clone())
            } else if url == "https://e.com/mac.tgz" {
                Ok(tgz_mac.clone())
            } else {
                Err(OpError::NotFound(url.to_string()))
            }
        };

        let artifacts = derive_binary_artifacts_with_fetcher(&spec, &fetcher).unwrap();
        assert_eq!(
            artifacts.len(),
            1,
            "should only derive 1 (linux), got {}",
            artifacts.len()
        );
        assert_eq!(artifacts[0].target, "x86_64-unknown-linux-gnu");
    }

    #[test]
    fn inner_binary_digest_not_tarball_digest() {
        let binary_content = b"the-real-binary";
        let inner_hex = sha256_hex(binary_content);
        let tgz = build_tgz("b-v1.0.0-x86_64-unknown-linux-gnu", "b", binary_content);
        let tarball_hex = sha256_hex(&tgz);
        // Sanity: the two digests differ.
        assert_ne!(inner_hex, tarball_hex);

        let sidecar = make_sidecar(&tgz, "b-v1.0.0-x86_64-unknown-linux-gnu.tgz");
        let release = release_json(&[
            (
                "b-v1.0.0-x86_64-unknown-linux-gnu.tgz",
                "https://e.com/b.tgz",
            ),
            (
                "b-v1.0.0-x86_64-unknown-linux-gnu.tgz.sha256",
                "https://e.com/b.tgz.sha256",
            ),
        ]);

        let spec = ReleaseSpec {
            owner: "t".to_string(),
            repo: "t".to_string(),
            binary_name: "b".to_string(),
            version: "1.0.0".to_string(),
            tag: "v1.0.0".to_string(),
            targets: vec![],
            expected_target_count: None,
            archive_prefix: None,
            checksums_asset: None,
        };

        let fetcher = move |url: &str| -> Result<Vec<u8>, OpError> {
            if url.contains("/releases/tags/") {
                Ok(release.clone())
            } else if url.ends_with(".sha256") {
                Ok(sidecar.as_bytes().to_vec())
            } else {
                Ok(tgz.clone())
            }
        };

        let artifacts = derive_binary_artifacts_with_fetcher(&spec, &fetcher).unwrap();
        assert_eq!(artifacts[0].digest, format!("sha256:{inner_hex}"));
        // Confirm it is NOT the tarball digest.
        assert_ne!(artifacts[0].digest, format!("sha256:{tarball_hex}"));
    }

    // --- Finding 3: multi-line sidecar rejection ---

    #[test]
    fn sidecar_multi_line_rejected() {
        let line1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  darwin.tgz";
        let line2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  linux.tgz";
        let multi = format!("{line1}\n{line2}\n");
        let err = parse_sidecar_digest(&multi).unwrap_err();
        assert!(
            matches!(&err, OpError::InvalidArgument(m) if m.contains("lines")),
            "expected multi-line rejection, got: {err:?}"
        );
    }

    // --- Finding 7: missing sidecar asset in release ---

    #[test]
    fn missing_sidecar_asset_fails() {
        // Release has the archive but not its .sha256 sidecar.
        let release = release_json(&[(
            "b-v1.0.0-x86_64-unknown-linux-gnu.tgz",
            "https://e.com/b.tgz",
        )]);

        let spec = ReleaseSpec {
            owner: "t".to_string(),
            repo: "t".to_string(),
            binary_name: "b".to_string(),
            version: "1.0.0".to_string(),
            tag: "v1.0.0".to_string(),
            targets: vec![],
            expected_target_count: None,
            archive_prefix: None,
            checksums_asset: None,
        };

        let fetcher = move |url: &str| -> Result<Vec<u8>, OpError> {
            if url.contains("/releases/tags/") {
                Ok(release.clone())
            } else {
                Err(OpError::NotFound(url.to_string()))
            }
        };

        let err = derive_binary_artifacts_with_fetcher(&spec, &fetcher).unwrap_err();
        assert!(
            matches!(&err, OpError::NotFound(m) if m.contains(".sha256")),
            "expected NotFound for missing sidecar, got: {err:?}"
        );
    }

    // --- Finding 8: no matching archives in release ---

    #[test]
    fn no_matching_archives_fails() {
        // Release has assets but none match the expected prefix.
        let release = release_json(&[
            ("unrelated-file.tgz", "https://e.com/unrelated.tgz"),
            (
                "unrelated-file.tgz.sha256",
                "https://e.com/unrelated.tgz.sha256",
            ),
        ]);

        let spec = ReleaseSpec {
            owner: "t".to_string(),
            repo: "t".to_string(),
            binary_name: "b".to_string(),
            version: "1.0.0".to_string(),
            tag: "v1.0.0".to_string(),
            targets: vec![],
            expected_target_count: None,
            archive_prefix: None,
            checksums_asset: None,
        };

        let fetcher = move |url: &str| -> Result<Vec<u8>, OpError> {
            if url.contains("/releases/tags/") {
                Ok(release.clone())
            } else {
                Err(OpError::NotFound(url.to_string()))
            }
        };

        let err = derive_binary_artifacts_with_fetcher(&spec, &fetcher).unwrap_err();
        assert!(
            matches!(&err, OpError::InvalidArgument(m) if m.contains("no archive assets matching")),
            "expected InvalidArgument for no matching archives, got: {err:?}"
        );
    }

    // --- Finding 1: expected target count mismatch ---

    #[test]
    fn expected_target_count_mismatch_fails() {
        // Release has 1 archive but we expect 2.
        let binary_content = b"binary";
        let tgz = build_tgz("b-v1.0.0-x86_64-unknown-linux-gnu", "b", binary_content);
        let sidecar = make_sidecar(&tgz, "b-v1.0.0-x86_64-unknown-linux-gnu.tgz");

        let release = release_json(&[
            (
                "b-v1.0.0-x86_64-unknown-linux-gnu.tgz",
                "https://e.com/b.tgz",
            ),
            (
                "b-v1.0.0-x86_64-unknown-linux-gnu.tgz.sha256",
                "https://e.com/b.tgz.sha256",
            ),
        ]);

        let spec = ReleaseSpec {
            owner: "t".to_string(),
            repo: "t".to_string(),
            binary_name: "b".to_string(),
            version: "1.0.0".to_string(),
            tag: "v1.0.0".to_string(),
            targets: vec![],
            expected_target_count: Some(2),
            archive_prefix: None,
            checksums_asset: None,
        };

        let fetcher = move |url: &str| -> Result<Vec<u8>, OpError> {
            if url.contains("/releases/tags/") {
                Ok(release.clone())
            } else if url.ends_with(".sha256") {
                Ok(sidecar.as_bytes().to_vec())
            } else {
                Ok(tgz.clone())
            }
        };

        let err = derive_binary_artifacts_with_fetcher(&spec, &fetcher).unwrap_err();
        assert!(
            matches!(&err, OpError::InvalidArgument(m) if m.contains("expected 2") && m.contains("found 1")),
            "expected count mismatch error, got: {err:?}"
        );
    }

    #[test]
    fn expected_target_count_matching_succeeds() {
        // Release has 1 archive and we expect 1.
        let binary_content = b"binary";
        let tgz = build_tgz("b-v1.0.0-x86_64-unknown-linux-gnu", "b", binary_content);
        let sidecar = make_sidecar(&tgz, "b-v1.0.0-x86_64-unknown-linux-gnu.tgz");

        let release = release_json(&[
            (
                "b-v1.0.0-x86_64-unknown-linux-gnu.tgz",
                "https://e.com/b.tgz",
            ),
            (
                "b-v1.0.0-x86_64-unknown-linux-gnu.tgz.sha256",
                "https://e.com/b.tgz.sha256",
            ),
        ]);

        let spec = ReleaseSpec {
            owner: "t".to_string(),
            repo: "t".to_string(),
            binary_name: "b".to_string(),
            version: "1.0.0".to_string(),
            tag: "v1.0.0".to_string(),
            targets: vec![],
            expected_target_count: Some(1),
            archive_prefix: None,
            checksums_asset: None,
        };

        let fetcher = move |url: &str| -> Result<Vec<u8>, OpError> {
            if url.contains("/releases/tags/") {
                Ok(release.clone())
            } else if url.ends_with(".sha256") {
                Ok(sidecar.as_bytes().to_vec())
            } else {
                Ok(tgz.clone())
            }
        };

        let artifacts = derive_binary_artifacts_with_fetcher(&spec, &fetcher).unwrap();
        assert_eq!(artifacts.len(), 1);
    }

    #[test]
    fn duplicate_target_triple_rejected() {
        // Both .tgz and .zip exist for the same target — should fail.
        let binary_content = b"binary";
        let tgz = build_tgz("b-v1.0.0-x86_64-unknown-linux-gnu", "b", binary_content);
        let zip_bytes = build_zip_archive("b-v1.0.0-x86_64-unknown-linux-gnu", "b", binary_content);

        let release = release_json(&[
            (
                "b-v1.0.0-x86_64-unknown-linux-gnu.tgz",
                "https://e.com/b.tgz",
            ),
            (
                "b-v1.0.0-x86_64-unknown-linux-gnu.tgz.sha256",
                "https://e.com/b.tgz.sha256",
            ),
            (
                "b-v1.0.0-x86_64-unknown-linux-gnu.zip",
                "https://e.com/b.zip",
            ),
            (
                "b-v1.0.0-x86_64-unknown-linux-gnu.zip.sha256",
                "https://e.com/b.zip.sha256",
            ),
        ]);

        let spec = ReleaseSpec {
            owner: "t".to_string(),
            repo: "t".to_string(),
            binary_name: "b".to_string(),
            version: "1.0.0".to_string(),
            tag: "v1.0.0".to_string(),
            targets: vec![],
            expected_target_count: None,
            archive_prefix: None,
            checksums_asset: None,
        };

        let fetcher = move |url: &str| -> Result<Vec<u8>, OpError> {
            if url.contains("/releases/tags/") {
                Ok(release.clone())
            } else if url.ends_with(".tgz.sha256") {
                Ok(make_sidecar(&tgz, "b-v1.0.0-x86_64-unknown-linux-gnu.tgz")
                    .as_bytes()
                    .to_vec())
            } else if url.ends_with(".zip.sha256") {
                Ok(
                    make_sidecar(&zip_bytes, "b-v1.0.0-x86_64-unknown-linux-gnu.zip")
                        .as_bytes()
                        .to_vec(),
                )
            } else if url.ends_with(".tgz") {
                Ok(tgz.clone())
            } else if url.ends_with(".zip") {
                Ok(zip_bytes.clone())
            } else {
                Err(OpError::NotFound(url.to_string()))
            }
        };

        let err = derive_binary_artifacts_with_fetcher(&spec, &fetcher).unwrap_err();
        assert!(
            matches!(&err, OpError::InvalidArgument(m) if m.contains("duplicate archives")),
            "expected duplicate target rejection, got: {err:?}"
        );
    }

    // --- parse_consolidated_checksums -----------------------------------------

    #[test]
    fn consolidated_checksums_happy_path() {
        let text = "\
            aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  gtc-x86_64-unknown-linux-gnu.tgz\n\
            bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  gtc-aarch64-apple-darwin.tgz\n";
        let map = parse_consolidated_checksums(text).unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(
            map.get("gtc-x86_64-unknown-linux-gnu.tgz").unwrap(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            map.get("gtc-aarch64-apple-darwin.tgz").unwrap(),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
    }

    #[test]
    fn consolidated_checksums_malformed_digest() {
        let text = "tooshort  file.tgz\n";
        let err = parse_consolidated_checksums(text).unwrap_err();
        assert!(
            matches!(&err, OpError::InvalidArgument(m) if m.contains("64 hex")),
            "expected malformed digest error, got: {err:?}"
        );
    }

    #[test]
    fn consolidated_checksums_missing_filename() {
        let text = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
        let err = parse_consolidated_checksums(text).unwrap_err();
        assert!(
            matches!(&err, OpError::InvalidArgument(m) if m.contains("missing filename")),
            "expected missing filename error, got: {err:?}"
        );
    }

    #[test]
    fn consolidated_checksums_empty() {
        let err = parse_consolidated_checksums("").unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    // --- derive_binary_artifacts with archive_prefix override -----------------

    #[test]
    fn derive_with_archive_prefix_override() {
        let binary_content = b"gtc-binary-content";
        let inner_digest = format!("sha256:{}", sha256_hex(binary_content));

        // gtc uses prefix "gtc-" (no version in the archive name).
        let tgz = build_tgz("gtc-x86_64-unknown-linux-gnu", "gtc", binary_content);
        let sidecar = make_sidecar(&tgz, "gtc-x86_64-unknown-linux-gnu.tgz");

        let release = release_json(&[
            (
                "gtc-x86_64-unknown-linux-gnu.tgz",
                "https://example.com/gtc-x86_64-unknown-linux-gnu.tgz",
            ),
            (
                "gtc-x86_64-unknown-linux-gnu.tgz.sha256",
                "https://example.com/gtc-x86_64-unknown-linux-gnu.tgz.sha256",
            ),
        ]);

        let spec = ReleaseSpec {
            owner: "greenticai".to_string(),
            repo: "greentic".to_string(),
            binary_name: "gtc".to_string(),
            version: "1.1.10".to_string(),
            tag: "v1.1.10".to_string(),
            targets: vec![],
            expected_target_count: None,
            archive_prefix: Some("gtc-".to_string()),
            checksums_asset: None,
        };

        let fetcher = move |url: &str| -> Result<Vec<u8>, OpError> {
            if url.contains("/releases/tags/") {
                Ok(release.clone())
            } else if url.ends_with(".sha256") {
                Ok(sidecar.as_bytes().to_vec())
            } else if url.ends_with(".tgz") {
                Ok(tgz.clone())
            } else {
                Err(OpError::NotFound(format!("unexpected URL: {url}")))
            }
        };

        let artifacts = derive_binary_artifacts_with_fetcher(&spec, &fetcher).unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].name, "gtc");
        assert_eq!(artifacts[0].version, "1.1.10");
        assert_eq!(artifacts[0].target, "x86_64-unknown-linux-gnu");
        assert_eq!(artifacts[0].digest, inner_digest);
    }

    // --- derive_binary_artifacts with checksums_asset -------------------------

    #[test]
    fn derive_with_checksums_asset() {
        // Simulates gtc-shaped release: archives named "gtc-{target}.tgz" plus
        // one consolidated "gtc-1.1.10-checksums.txt" instead of per-archive
        // .sha256 sidecars.
        let linux_content = b"gtc-linux-bin";
        let mac_content = b"gtc-mac-bin";

        let tgz_linux = build_tgz("gtc-x86_64-unknown-linux-gnu", "gtc", linux_content);
        let tgz_mac = build_tgz("gtc-aarch64-apple-darwin", "gtc", mac_content);

        let checksums_text = format!(
            "{}  gtc-x86_64-unknown-linux-gnu.tgz\n{}  gtc-aarch64-apple-darwin.tgz\n",
            sha256_hex(&tgz_linux),
            sha256_hex(&tgz_mac),
        );

        let release = release_json(&[
            (
                "gtc-x86_64-unknown-linux-gnu.tgz",
                "https://example.com/gtc-x86_64-unknown-linux-gnu.tgz",
            ),
            (
                "gtc-aarch64-apple-darwin.tgz",
                "https://example.com/gtc-aarch64-apple-darwin.tgz",
            ),
            (
                "gtc-1.1.10-checksums.txt",
                "https://example.com/gtc-1.1.10-checksums.txt",
            ),
        ]);

        let spec = ReleaseSpec {
            owner: "greenticai".to_string(),
            repo: "greentic".to_string(),
            binary_name: "gtc".to_string(),
            version: "1.1.10".to_string(),
            tag: "v1.1.10".to_string(),
            targets: vec![],
            expected_target_count: None,
            archive_prefix: Some("gtc-".to_string()),
            checksums_asset: Some("gtc-1.1.10-checksums.txt".to_string()),
        };

        let fetcher = move |url: &str| -> Result<Vec<u8>, OpError> {
            if url.contains("/releases/tags/") {
                Ok(release.clone())
            } else if url.ends_with("checksums.txt") {
                Ok(checksums_text.as_bytes().to_vec())
            } else if url.contains("linux") {
                Ok(tgz_linux.clone())
            } else if url.contains("darwin") {
                Ok(tgz_mac.clone())
            } else {
                Err(OpError::NotFound(format!("unexpected URL: {url}")))
            }
        };

        let artifacts = derive_binary_artifacts_with_fetcher(&spec, &fetcher).unwrap();
        assert_eq!(artifacts.len(), 2);
        let linux = artifacts
            .iter()
            .find(|a| a.target == "x86_64-unknown-linux-gnu")
            .unwrap();
        let mac = artifacts
            .iter()
            .find(|a| a.target == "aarch64-apple-darwin")
            .unwrap();
        assert_eq!(
            linux.digest,
            format!("sha256:{}", sha256_hex(linux_content))
        );
        assert_eq!(mac.digest, format!("sha256:{}", sha256_hex(mac_content)));
    }
}
