//! Staging one revision's seed into Secrets Manager (decision record
//! `docs/aws-ecs-seed-and-bundle-delivery.md` section 3).
//!
//! Each seed file is its own secret, written as a content-addressed version
//! and referenced from the task definition by `<arn>:::<version-id>`, so the
//! values never enter the task definition:
//!
//! | File | Secret | Reaches |
//! |---|---|---|
//! | `environment.json` (pruned to this revision) | `<prefix>-environment` | `seed-init` |
//! | `.greentic/dev/.dev.secrets.env` (only when the env has one) | `<prefix>-dev-store` | `seed-init` |
//! | telemetry headers (only when answered) | `<prefix>-telemetry-headers` | the worker's `secrets`, never `environment` |
//!
//! Every value is checked BEFORE any secret is created or written, so an
//! oversized seed leaves nothing half-staged.

use greentic_deploy_spec::{Environment, RevisionId};

use super::deploy_target::{
    EcsDeployTarget, EnsuredSecret, SecretEnvRef, SecretVersionRef, SeedFile, SeedInit,
};
use super::deployer::AwsEcsParams;
use super::seed_init::SEED_INIT_IMAGE;
use crate::cli::secrets::DEV_STORE_RELATIVE;
use crate::env_packs::deployer::DeployerError;
use crate::env_packs::owner_stamp::env_owner_stamp;
use crate::env_packs::telemetry::HEADER_ENV_NAMES;
use crate::environment::seed::seed_environment_bytes;

/// Largest seed file the ECS lane stages: one Secrets Manager secret value.
pub(crate) const SEED_MAX_BYTES: usize = 65_536;

/// File name of the environment seed under `/seed`.
pub(crate) const ENVIRONMENT_SEED_FILE: &str = "environment.json";

/// Secret carrying the environment seed: `<secret_prefix>-environment`.
pub(crate) fn environment_secret_name(secret_prefix: &str) -> String {
    format!("{secret_prefix}-environment")
}

/// Secret carrying the dev store: `<secret_prefix>-dev-store`.
pub(crate) fn dev_store_secret_name(secret_prefix: &str) -> String {
    format!("{secret_prefix}-dev-store")
}

/// Secret carrying the telemetry headers: `<secret_prefix>-telemetry-headers`.
pub(crate) fn telemetry_headers_secret_name(secret_prefix: &str) -> String {
    format!("{secret_prefix}-telemetry-headers")
}

/// Why a seed value was refused before staging. Never truncated, never split.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum SeedRefusal {
    #[error(
        "seed file `{file}` is {bytes} bytes, over the {limit}-byte limit of one Secrets Manager \
         secret value; the ECS lane refuses rather than truncating it. Archive revisions nothing \
         routes to, or remove unused secrets, to shrink it"
    )]
    TooLarge {
        file: String,
        bytes: usize,
        limit: usize,
    },
    #[error("seed file `{file}` is not valid UTF-8, so it cannot be a Secrets Manager string")]
    NotUtf8 { file: String },
    #[error("seed file `{file}` contains a NUL byte, which an environment variable cannot carry")]
    ContainsNul { file: String },
}

/// Check one value against the decision record's rules (section 3.1).
pub(crate) fn check_seed_value(file: &str, bytes: &[u8]) -> Result<(), SeedRefusal> {
    if bytes.len() > SEED_MAX_BYTES {
        return Err(SeedRefusal::TooLarge {
            file: file.to_string(),
            bytes: bytes.len(),
            limit: SEED_MAX_BYTES,
        });
    }
    if std::str::from_utf8(bytes).is_err() {
        return Err(SeedRefusal::NotUtf8 {
            file: file.to_string(),
        });
    }
    if bytes.contains(&0) {
        return Err(SeedRefusal::ContainsNul {
            file: file.to_string(),
        });
    }
    Ok(())
}

/// What staging produced for the task definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StagedSeed {
    pub seed: SeedInit,
    pub secret_env: Vec<SecretEnvRef>,
}

/// The refusal for a secret this environment does not own. An EMPTY owner is
/// foreign too: unlike Cloud Run there is no legacy unstamped ECS secret to
/// adopt, so an unstamped secret was made by someone else.
pub(crate) fn secret_owner_conflict(name: &str, owner: &str, env_id: &str) -> DeployerError {
    let held = if owner.is_empty() {
        "carries no `greentic:owner` tag".to_string()
    } else {
        format!("belongs to environment `{owner}`")
    };
    DeployerError::Provider(format!(
        "Secrets Manager secret `{name}` {held}, but this is environment `{ours}`. The deployer \
         only writes secrets it created for this environment. Give this environment a distinct \
         `secret_prefix` answer.",
        ours = env_owner_stamp(env_id),
    ))
}

/// Claim `name` for `env_id` (refusing one owned by anyone else), then store
/// `bytes` as a content-addressed version.
async fn claim_and_put(
    target: &dyn EcsDeployTarget,
    name: &str,
    env_id: &str,
    bytes: &[u8],
) -> Result<SecretVersionRef, DeployerError> {
    let ours = env_owner_stamp(env_id);
    let ensured = target
        .ensure_secret(name, &ours)
        .await
        .map_err(|e| DeployerError::Provider(e.to_string()))?;
    if let EnsuredSecret::Existed { owner } = ensured
        && owner != ours
    {
        return Err(secret_owner_conflict(name, &owner, env_id));
    }
    target
        .put_secret_value(name, bytes)
        .await
        .map_err(|e| DeployerError::Provider(e.to_string()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// Stage the revision's seed files and the telemetry header secret.
pub(crate) async fn stage(
    target: &dyn EcsDeployTarget,
    env: &Environment,
    revision_id: RevisionId,
    params: &AwsEcsParams,
    dev_secrets: Option<&[u8]>,
) -> Result<StagedSeed, DeployerError> {
    let environment_json = seed_environment_bytes(env, &[revision_id]).map_err(|e| {
        DeployerError::Provider(format!(
            "serializing environment.json for seed staging: {e}"
        ))
    })?;
    let headers = params.telemetry.headers().map(|h| h.expose().as_bytes());

    // Every value is checked before the first AWS write.
    let refuse = |e: SeedRefusal| DeployerError::Provider(e.to_string());
    check_seed_value(ENVIRONMENT_SEED_FILE, &environment_json).map_err(refuse)?;
    if let Some(dev) = dev_secrets {
        check_seed_value(DEV_STORE_RELATIVE, dev).map_err(refuse)?;
    }
    if let Some(h) = headers {
        check_seed_value("telemetry headers", h).map_err(refuse)?;
    }

    let env_id = env.environment_id.as_str();
    let prefix = &params.secret_prefix;
    let env_version = claim_and_put(
        target,
        &environment_secret_name(prefix),
        env_id,
        &environment_json,
    )
    .await?;
    let mut files = vec![SeedFile {
        name: ENVIRONMENT_SEED_FILE.to_string(),
        secret_value_from: env_version.value_from(),
        sha256_hex: sha256_hex(&environment_json),
    }];
    if let Some(dev) = dev_secrets {
        let dev_version =
            claim_and_put(target, &dev_store_secret_name(prefix), env_id, dev).await?;
        files.push(SeedFile {
            name: DEV_STORE_RELATIVE.to_string(),
            secret_value_from: dev_version.value_from(),
            sha256_hex: sha256_hex(dev),
        });
    }
    let mut secret_env = Vec::new();
    if let Some(h) = headers {
        let version =
            claim_and_put(target, &telemetry_headers_secret_name(prefix), env_id, h).await?;
        for name in HEADER_ENV_NAMES {
            secret_env.push(SecretEnvRef {
                name: name.to_string(),
                value_from_arn: version.value_from(),
            });
        }
    }
    Ok(StagedSeed {
        seed: SeedInit {
            image: SEED_INIT_IMAGE.to_string(),
            files,
        },
        secret_env,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_seed_value_names_the_file_size_and_limit() {
        let big = vec![b'a'; SEED_MAX_BYTES + 1];
        let err = check_seed_value("environment.json", &big).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("environment.json"), "{msg}");
        assert!(msg.contains(&(SEED_MAX_BYTES + 1).to_string()), "{msg}");
        assert!(msg.contains("65536"), "{msg}");
        assert!(check_seed_value("f", &vec![b'a'; SEED_MAX_BYTES]).is_ok());
    }

    #[test]
    fn check_seed_value_refuses_non_utf8_and_nul() {
        assert_eq!(
            check_seed_value("f", &[0xff, 0xfe]),
            Err(SeedRefusal::NotUtf8 { file: "f".into() })
        );
        assert_eq!(
            check_seed_value("f", b"a\0b"),
            Err(SeedRefusal::ContainsNul { file: "f".into() })
        );
    }

    #[test]
    fn an_empty_owner_is_described_as_unstamped() {
        let msg = secret_owner_conflict("s", "", "env").to_string();
        assert!(msg.contains("no `greentic:owner` tag"), "{msg}");
    }
}
