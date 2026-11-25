//! Versioned encrypted-store transport shared by deployer and runtime.
//! Digests cover the encrypted bytes; this module never decrypts or logs them.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SECRET_VERSION_CAP: usize = 65_536;
pub const CHUNK_BYTES: usize = 60 * 1024;
pub const MAX_CHUNKS: usize = 64;
pub const MAX_STORE_BYTES: usize = CHUNK_BYTES * MAX_CHUNKS;
pub const SCHEMA: &str = "greentic.secret-store.chunks.v1";
pub const TRANSPORT_ENV: &str = "GREENTIC_SECRET_STORE_TRANSPORT";
pub const IMAGE_CAPABILITY_LABEL: &str = "io.greentic.secret-store.chunks";
pub const MANIFEST_PATH: &str = ".greentic/dev/.dev.secrets.chunks.v1.json";
pub const CHUNK_DIR: &str = ".greentic/dev/.dev.secrets.chunks.v1";
pub const STORE_PATH: &str = ".greentic/dev/.dev.secrets.env";

/// All failures are static: even malformed JSON must never echo a secret value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("encrypted secret-store transport: {0}")]
pub struct ChunkError(pub &'static str);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Chunk {
    pub index: usize,
    pub path: String,
    pub version: String,
    pub length: usize,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChunkManifest {
    pub schema: String,
    pub length: usize,
    pub sha256: String,
    pub chunks: Vec<Chunk>,
}

pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn chunk_path(index: usize) -> String {
    format!("{CHUNK_DIR}/{index:06}.bin")
}

pub fn check_store_length(length: usize) -> Result<(), ChunkError> {
    if length <= SECRET_VERSION_CAP || length > MAX_STORE_BYTES {
        return Err(ChunkError(
            "chunked store length is outside protocol bounds",
        ));
    }
    Ok(())
}

/// Numeric immutable versions only; no `latest`, aliases, or resource paths.
pub fn numeric_version(version: &str) -> bool {
    !version.is_empty()
        && !version.starts_with('0')
        && version.bytes().all(|b| b.is_ascii_digit())
        && version.parse::<u64>().is_ok()
}

fn hash_valid(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl ChunkManifest {
    pub fn new(bytes: &[u8], versions: &[String]) -> Result<Self, ChunkError> {
        check_store_length(bytes.len())?;
        if versions.len() != bytes.len().div_ceil(CHUNK_BYTES) {
            return Err(ChunkError("uploaded chunk count does not match the store"));
        }
        let manifest = Self {
            schema: SCHEMA.into(),
            length: bytes.len(),
            sha256: digest(bytes),
            chunks: bytes
                .chunks(CHUNK_BYTES)
                .zip(versions)
                .enumerate()
                .map(|(index, (bytes, version))| Chunk {
                    index,
                    path: chunk_path(index),
                    version: version.clone(),
                    length: bytes.len(),
                    sha256: digest(bytes),
                })
                .collect(),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), ChunkError> {
        check_store_length(self.length)?;
        if self.schema != SCHEMA
            || !hash_valid(&self.sha256)
            || self.chunks.len() != self.length.div_ceil(CHUNK_BYTES)
        {
            return Err(ChunkError("invalid schema, store digest, or chunk count"));
        }
        let mut versions = BTreeSet::new();
        for (index, chunk) in self.chunks.iter().enumerate() {
            let expected_len = (self.length - index * CHUNK_BYTES).min(CHUNK_BYTES);
            if chunk.index != index
                || chunk.path != chunk_path(index)
                || chunk.length != expected_len
                || !hash_valid(&chunk.sha256)
                || !numeric_version(&chunk.version)
                || !versions.insert(&chunk.version)
            {
                return Err(ChunkError(
                    "invalid chunk order, path, length, digest, or duplicate version",
                ));
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ChunkError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| ChunkError("cannot encode manifest"))?;
        if bytes.len() > SECRET_VERSION_CAP {
            return Err(ChunkError("manifest exceeds version capacity"));
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ChunkError> {
        if bytes.len() > SECRET_VERSION_CAP {
            return Err(ChunkError("manifest exceeds version capacity"));
        }
        let manifest: Self =
            serde_json::from_slice(bytes).map_err(|_| ChunkError("invalid manifest JSON"))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// A reader must bound each read to CHUNK_BYTES + 1, including untrusted mounts.
    /// Validate everything before the caller installs any output file.
    pub fn reconstruct(
        &self,
        mut read: impl FnMut(&Chunk) -> Result<Vec<u8>, ChunkError>,
    ) -> Result<Vec<u8>, ChunkError> {
        self.validate()?;
        let mut store = Vec::with_capacity(self.length);
        for chunk in &self.chunks {
            let bytes = read(chunk)?;
            if bytes.len() != chunk.length || digest(&bytes) != chunk.sha256 {
                return Err(ChunkError("chunk length or integrity check failed"));
            }
            store.extend_from_slice(&bytes);
        }
        if store.len() != self.length || digest(&store) != self.sha256 {
            return Err(ChunkError("store length or integrity check failed"));
        }
        Ok(store)
    }
}

#[cfg(test)]
mod tests;
