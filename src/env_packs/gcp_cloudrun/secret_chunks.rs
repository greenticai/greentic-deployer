//! Chunk staging policy. The transport codec is shared with greentic-start.
use greentic_deploy_spec::secret_chunks::{self as protocol, ChunkManifest};

use super::deploy_target::{CloudRunTarget, CloudRunTargetError, SecretMountItem};

pub fn pinned_image_digest(image: &str) -> Option<&str> {
    let (_, digest) = image.rsplit_once("@sha256:")?;
    (digest.len() == 64
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then_some(digest)
}

/// Check before any seed upload, secret claim, grant, or service mutation.
pub async fn preflight(
    target: &dyn CloudRunTarget,
    image: &str,
    bytes: &[u8],
) -> Result<(), CloudRunTargetError> {
    if bytes.len() <= protocol::SECRET_VERSION_CAP {
        return Ok(());
    }
    protocol::check_store_length(bytes.len()).map_err(|_| CloudRunTargetError::Api(format!(
        "encrypted dev store is {} bytes; chunked transport v1 supports at most {} bytes in {} chunks; no seed was staged",
        bytes.len(), protocol::MAX_STORE_BYTES, protocol::MAX_CHUNKS,
    )))?;
    if pinned_image_digest(image).is_none() || !target.supports_secret_chunks(image).await? {
        return Err(CloudRunTargetError::Api(format!(
            "encrypted dev store is {} bytes (single-version limit {}); chunked transport requires a digest-pinned runtime image with verified {}=1 capability; upgrade the runtime and pin its digest",
            bytes.len(),
            protocol::SECRET_VERSION_CAP,
            protocol::IMAGE_CAPABILITY_LABEL,
        )));
    }
    Ok(())
}

/// Publish the manifest last. Failed attempts leave only unreferenced immutable
/// versions; never destroy rollback versions or expose a partially uploaded tree.
pub async fn stage(
    target: &dyn CloudRunTarget,
    secret: &str,
    bytes: &[u8],
) -> Result<Vec<SecretMountItem>, CloudRunTargetError> {
    protocol::check_store_length(bytes.len())
        .map_err(|e| CloudRunTargetError::Api(e.to_string()))?;
    let mut versions = Vec::new();
    for chunk in bytes.chunks(protocol::CHUNK_BYTES) {
        let version = target.add_secret_version(secret, chunk).await?.version;
        if !protocol::numeric_version(&version) || versions.contains(&version) {
            return Err(CloudRunTargetError::Api(
                "chunk upload returned an invalid or duplicate immutable version".into(),
            ));
        }
        versions.push(version);
    }
    let manifest = ChunkManifest::new(bytes, &versions)
        .map_err(|e| CloudRunTargetError::Api(e.to_string()))?;
    let payload = manifest
        .encode()
        .map_err(|e| CloudRunTargetError::Api(e.to_string()))?;
    let version = target.add_secret_version(secret, &payload).await?.version;
    if !protocol::numeric_version(&version) || versions.contains(&version) {
        return Err(CloudRunTargetError::Api(
            "manifest upload returned an invalid immutable version".into(),
        ));
    }
    let mut items: Vec<_> = manifest
        .chunks
        .into_iter()
        .map(|c| SecretMountItem {
            version: c.version,
            rel_path: c.path,
        })
        .collect();
    items.push(SecretMountItem {
        version,
        rel_path: protocol::MANIFEST_PATH.into(),
    });
    Ok(items)
}

/// Machine-readable CLI contract for Designer's capacity preflight.
pub fn capability_report() -> serde_json::Value {
    serde_json::json!({
        "schema": protocol::SCHEMA,
        "legacy_max_bytes": protocol::SECRET_VERSION_CAP,
        "chunk_bytes": protocol::CHUNK_BYTES,
        "max_chunks": protocol::MAX_CHUNKS,
        "max_store_bytes": protocol::MAX_STORE_BYTES,
        "runtime_image_capability_label": protocol::IMAGE_CAPABILITY_LABEL,
        "runtime_image_capability_value": "1",
        "requires_verified_digest_pin": true,
        "live_deploy": cfg!(feature = "deploy-gcp-cloudrun"),
    })
}

/// Validate a fetched OCI config, not an operator's unverified boolean answer.
/// The caller must bind this config to the exact image manifest/index digest.
pub fn config_advertises_chunks(config: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(config)
        .ok()
        .and_then(|v| {
            v.get("config")?
                .get("Labels")?
                .get(protocol::IMAGE_CAPABILITY_LABEL)?
                .as_str()
                .map(str::to_owned)
        })
        .as_deref()
        == Some("1")
}

/// Bind the advertised capability to the exact fetched artifact, including an
/// OCI index pin and its selected linux/amd64 config. Registry error bodies and
/// config parse errors never become operator diagnostics.
pub fn verify_image_capability(
    image: &str,
    manifest_digest: &str,
    index_digest: Option<&str>,
    config_digest: &str,
    config: &str,
) -> Result<bool, CloudRunTargetError> {
    let Some(pin) = pinned_image_digest(image) else {
        return Ok(false);
    };
    if index_digest.unwrap_or(manifest_digest) != format!("sha256:{pin}") {
        return Err(CloudRunTargetError::Api(
            "runtime capability image digest mismatch".into(),
        ));
    }
    if config_digest != format!("sha256:{}", protocol::digest(config.as_bytes())) {
        return Err(CloudRunTargetError::Api(
            "runtime capability config digest mismatch".into(),
        ));
    }
    let value: serde_json::Value = serde_json::from_str(config)
        .map_err(|_| CloudRunTargetError::Api("invalid runtime capability config".into()))?;
    Ok(value["os"] == "linux"
        && value["architecture"] == "amd64"
        && config_advertises_chunks(config))
}

#[cfg(test)]
mod tests;
