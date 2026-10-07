//! The `seed_mode` answer and the pointer seed.
//!
//! Secret Manager caps one secret version at 65,536 bytes, and
//! `environment.json` — the seed a Cloud Run worker boots from — can outgrow it
//! even after [`prune_for_seed`](crate::environment::prune_for_seed) removed
//! every revision the worker never reads (a live set of many units, each with
//! several packs). `seed_mode = auto` lifts the cap: a seed larger than
//! [`SEED_INLINE_THRESHOLD`] is pushed to the environment's Artifact Registry
//! repository as an OCI artifact and the secret version carries a small
//! POINTER instead, which greentic-start resolves at boot.
//!
//! ## The pointer is a cross-repo contract
//!
//! ```json
//! {"$greentic_seed_pointer":1,"kind":"oci","uri":"<registry-path>@sha256:<manifest digest>","sha256":"<hex of the ORIGINAL compact environment.json>","size":<original byte length>}
//! ```
//!
//! greentic-start detects the `$greentic_seed_pointer` key in the mounted
//! `environment.json`, pulls `uri` with the runtime service account's metadata
//! token, verifies `sha256` over the pulled bytes and writes them as the real
//! `environment.json`. Do not change the shape or the field order. `uri` has no
//! `oci://` scheme (the `kind` field already says so) and is pinned by the OCI
//! MANIFEST digest — the only digest a registry resolves an `@sha256:` suffix
//! against; `sha256` is the digest of the document itself.
//!
//! ## Where it lives and who pushes
//!
//! `<host>/<project>/<repo>/seed/<env-id>:<12 hex of sha256>`, in the SAME
//! Artifact Registry repository the revision's bundle was pulled from (read off
//! the revision's `oci://…-docker.pkg.dev/<project>/<repo>/…` source, via
//! [`ar_repository`]), so the runtime service account that already pulls the
//! bundle can pull the seed with the grant it already has. The push is done by
//! the deployer's own bound credential — the identity that pushes the bundle —
//! through [`CloudRunTarget::push_seed_artifact`]; the real target reuses
//! `MonolithicRegistryPusher`, the same transport `bundle-upload oci://` uses
//! (Artifact Registry refuses `oci-client`'s default chunked push past the first
//! chunk). The tag is content-addressed, so an unchanged seed re-pushes to the
//! same manifest, and a pointer is immutable by digest regardless of the tag.
//!
//! Superseded seed artifacts are never deleted by the deployer; they are small
//! and share the repository's own cleanup policy.

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::deploy_target::{CloudRunTarget, CloudRunTargetError};
use super::sor::spec::ar_repository;

/// Secret Manager's per-version payload cap.
pub const SECRET_VERSION_CAP: usize = 65_536;

/// Under `auto`, a seed larger than this goes out as a pointer. Below the hard
/// cap on purpose: the version also has to survive growth between deploys, and
/// the pointer path is only worth taking when inline is genuinely at risk.
pub const SEED_INLINE_THRESHOLD: usize = 48 * 1024;

/// The key greentic-start looks for in the mounted `environment.json`.
pub const POINTER_KEY: &str = "$greentic_seed_pointer";

/// The `seed_mode` wizard answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SeedMode {
    /// Stage the (pruned) seed as the secret version itself. The default, and
    /// exactly what the deployer did before the answer existed.
    #[default]
    Inline,
    /// Inline while the seed fits [`SEED_INLINE_THRESHOLD`]; a pointer beyond.
    Auto,
}

impl SeedMode {
    /// Parse an answer value (`inline` | `auto`, case-insensitive).
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "inline" => Some(Self::Inline),
            "auto" => Some(Self::Auto),
            _ => None,
        }
    }
}

#[derive(Serialize)]
struct SeedPointer<'a> {
    #[serde(rename = "$greentic_seed_pointer")]
    version: u8,
    kind: &'static str,
    uri: &'a str,
    sha256: String,
    size: usize,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The pointer document for `original` (the compact `environment.json` bytes),
/// stored at `uri` (`<registry-path>@sha256:<manifest digest>`).
pub fn pointer_bytes(uri: &str, original: &[u8]) -> Vec<u8> {
    let pointer = SeedPointer {
        version: 1,
        kind: "oci",
        uri,
        sha256: sha256_hex(original),
        size: original.len(),
    };
    // A struct of strings and integers cannot fail to serialize.
    serde_json::to_vec(&pointer).unwrap_or_default()
}

/// Where the seed artifact is pushed, or why it cannot be.
///
/// `source_uri` is a revision's `bundle_source_uri`; only an Artifact Registry
/// `oci://` source names a repository the runtime account can read.
pub fn seed_reference(env_id: &str, source_uri: Option<&str>, original: &[u8]) -> Option<String> {
    let repo = ar_repository(source_uri?)?;
    let name = env_id.to_ascii_lowercase();
    let valid = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.'));
    if !valid {
        return None;
    }
    Some(format!(
        "{}-docker.pkg.dev/{}/{}/seed/{}:{}",
        repo.location,
        repo.project,
        repo.repository,
        name,
        &sha256_hex(original)[..12]
    ))
}

/// What to stage as the `environment.json` secret version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StagedSeed {
    /// The seed itself, byte for byte.
    Inline(Vec<u8>),
    /// A pointer to the artifact pushed at `reference`.
    Pointer { bytes: Vec<u8>, reference: String },
}

impl StagedSeed {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Inline(b) | Self::Pointer { bytes: b, .. } => b,
        }
    }
}

/// Decide inline or pointer for `seed`, pushing the artifact when needed.
///
/// Inline whenever the mode is `inline` or the seed fits the threshold. If a
/// pointer is wanted but cannot be made (no Artifact Registry source to derive
/// the repository from, or the push fails), the seed stays inline when it still
/// fits one Secret Manager version — a warning, not a failure — and is an error
/// otherwise, naming the cause rather than letting the secret write fail with a
/// bare size error.
pub async fn stage_seed(
    target: &dyn CloudRunTarget,
    mode: SeedMode,
    env_id: &str,
    source_uri: Option<&str>,
    seed: Vec<u8>,
) -> Result<StagedSeed, CloudRunTargetError> {
    if mode == SeedMode::Inline || seed.len() <= SEED_INLINE_THRESHOLD {
        return Ok(StagedSeed::Inline(seed));
    }
    let outcome = match seed_reference(env_id, source_uri, &seed) {
        None => Err(CloudRunTargetError::Api(
            "seed_mode `auto` needs the revision's bundle to come from an Artifact Registry \
             `oci://<location>-docker.pkg.dev/<project>/<repo>/…` source to place the seed \
             artifact beside it"
                .to_string(),
        )),
        Some(reference) => target
            .push_seed_artifact(&reference, &seed)
            .await
            .map(|manifest_digest| (reference, manifest_digest)),
    };
    match outcome {
        Ok((reference, manifest_digest)) => {
            // `<registry-path>@sha256:<manifest digest>`: drop the tag.
            let path = reference
                .rsplit_once(':')
                .map_or(reference.as_str(), |(path, _tag)| path);
            let digest = manifest_digest
                .strip_prefix("sha256:")
                .unwrap_or(&manifest_digest);
            let uri = format!("{path}@sha256:{digest}");
            tracing::info!(
                env = env_id,
                size = seed.len(),
                uri = %uri,
                "environment seed staged as an OCI pointer"
            );
            Ok(StagedSeed::Pointer {
                bytes: pointer_bytes(&uri, &seed),
                reference,
            })
        }
        Err(err) if seed.len() <= SECRET_VERSION_CAP => {
            tracing::warn!(
                env = env_id,
                error = %err,
                "could not stage the environment seed as a pointer; staging it inline"
            );
            Ok(StagedSeed::Inline(seed))
        }
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests;
