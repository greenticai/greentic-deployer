//! Seed model: validation, content-addressed secret names and the init script.
//!
//! Decision record: `docs/azure-aca-seed-and-bundle-delivery.md`.

use sha2::{Digest, Sha256};

/// Env-var ceiling for one seed file (`NEEDS_LIVE`; conservative).
pub(crate) const SEED_MAX_BYTES: usize = 24_576;
/// File name of the environment seed under `/seed`.
pub(crate) const ENVIRONMENT_SEED_FILE: &str = "environment.json";
/// Dev store relative path under `/seed`.
pub(crate) const DEV_STORE_FILE: &str = crate::cli::secrets::DEV_STORE_RELATIVE;
/// Busybox init image, pinned by index digest (public registry ACA can reach).
pub(crate) const SEED_INIT_IMAGE: &str = "docker.io/library/busybox:1.37.0-musl@sha256:5cec3fc171c87218698e85a52af7087de727372aae264a787b8112901a5b0092";
pub(crate) const SEED_INIT_CONTAINER: &str = "seed-init";
pub(crate) const SEED_VOLUME: &str = "seed";
pub(crate) const SEED_MOUNT_DIR: &str = "/seed";

// Delivery: each seed file is a `secretRef` env var of the init container (the one
// `NEEDS_LIVE` choice; a secret volume would raise the size cap). Only this
// mechanism is implemented, see the decision record.

/// One seed file.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SeedFile {
    pub name: String,
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for SeedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SeedFile({}, <redacted {} bytes>)",
            self.name,
            self.bytes.len()
        )
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum SeedError {
    #[error(
        "seed file `{name}` is {size} bytes, over the {limit}-byte limit of one Container Apps \
         secret; refusing rather than truncating. Archive revisions nothing routes to to shrink it"
    )]
    TooLarge {
        name: String,
        size: usize,
        limit: usize,
    },
    #[error("seed file `{name}` is not valid UTF-8")]
    NotUtf8 { name: String },
    #[error("seed file `{name}` contains a NUL byte, which an environment variable cannot carry")]
    ContainsNul { name: String },
    #[error(
        "seed file name {0:?} is not allowed (use [A-Za-z0-9._/-], no leading `/`, no `.`/`..`/empty components)"
    )]
    BadName(String),
    #[error("seed files {first:?} and {second:?} map to the same env var")]
    Collision { first: String, second: String },
}

/// Checks run BEFORE any ARM write.
pub(crate) fn validate_seed(file: &SeedFile) -> Result<(), SeedError> {
    validate_name(&file.name)?;
    check_value(&file.name, &file.bytes)
}

/// Size / encoding checks for any value staged as an ACA secret.
pub(crate) fn check_value(name: &str, bytes: &[u8]) -> Result<(), SeedError> {
    if bytes.len() > SEED_MAX_BYTES {
        return Err(SeedError::TooLarge {
            name: name.to_string(),
            size: bytes.len(),
            limit: SEED_MAX_BYTES,
        });
    }
    if std::str::from_utf8(bytes).is_err() {
        return Err(SeedError::NotUtf8 {
            name: name.to_string(),
        });
    }
    if bytes.contains(&0) {
        return Err(SeedError::ContainsNul {
            name: name.to_string(),
        });
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), SeedError> {
    let bad = name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
        || name
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..");
    if bad {
        Err(SeedError::BadName(name.to_string()))
    } else {
        Ok(())
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Content-addressed ACA secret name: `<prefix>-<12 hex of sha256>`. Lowercase
/// alphanumerics and `-` only, as ACA requires.
pub(crate) fn seed_secret_name(prefix: &str, bytes: &[u8]) -> String {
    format!("{prefix}-{}", &sha256_hex(bytes)[..12])
}

/// Secret name for a seed file (`seed-env-…` / `seed-dev-…`).
pub(crate) fn file_secret_name(file: &SeedFile) -> String {
    let prefix = if file.name == ENVIRONMENT_SEED_FILE {
        "seed-env"
    } else {
        "seed-dev"
    };
    seed_secret_name(prefix, &file.bytes)
}

fn var_stem(name: &str) -> String {
    match name {
        ENVIRONMENT_SEED_FILE => "ENVIRONMENT_JSON".to_string(),
        DEV_STORE_FILE => "DEV_STORE".to_string(),
        other => other
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .collect(),
    }
}

pub(crate) fn content_var(file: &SeedFile) -> String {
    format!("GREENTIC_SEED_{}", var_stem(&file.name))
}

pub(crate) fn sha_var(file: &SeedFile) -> String {
    format!("{}_SHA256", content_var(file))
}

/// The init container `sh -c` script: write each file byte for byte, verify digest.
pub(crate) fn init_script(files: &[SeedFile]) -> Result<String, SeedError> {
    let mut seen: Vec<(String, &str)> = Vec::new();
    for f in files {
        validate_name(&f.name)?;
        let stem = var_stem(&f.name);
        if let Some((_, first)) = seen.iter().find(|(s, _)| *s == stem) {
            return Err(SeedError::Collision {
                first: (*first).to_string(),
                second: f.name.clone(),
            });
        }
        seen.push((stem, &f.name));
    }
    let mut out = String::from("set -eu\numask 022\n");
    for f in files {
        let path = format!("{SEED_MOUNT_DIR}/{}", f.name);
        if let Some((dir, _)) = f.name.rsplit_once('/') {
            out.push_str(&format!("mkdir -p {SEED_MOUNT_DIR}/{dir}\n"));
        }
        out.push_str(&format!("printf '%s' \"${}\" > {path}\n", content_var(f)));
        out.push_str(&format!(
            "echo \"${}  {path}\" | sha256sum -c -s\n",
            sha_var(f)
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(name: &str, body: &str) -> SeedFile {
        SeedFile {
            name: name.into(),
            bytes: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn oversize_nul_or_non_utf8_is_refused_with_a_named_error() {
        let big = SeedFile {
            name: "environment.json".into(),
            bytes: vec![b'a'; SEED_MAX_BYTES + 1],
        };
        let e = validate_seed(&big).unwrap_err();
        assert!(matches!(e, SeedError::TooLarge { .. }));
        assert!(e.to_string().contains("environment.json"));
        assert!(matches!(
            validate_seed(&f("environment.json", "a\0b")),
            Err(SeedError::ContainsNul { .. })
        ));
        let bad = SeedFile {
            name: "environment.json".into(),
            bytes: vec![0xff],
        };
        assert!(matches!(
            validate_seed(&bad),
            Err(SeedError::NotUtf8 { .. })
        ));
        assert!(validate_seed(&f("environment.json", "{}")).is_ok());
    }

    #[test]
    fn secret_name_is_deterministic_and_changes_with_content() {
        let a = file_secret_name(&f("environment.json", "one"));
        assert_eq!(a, file_secret_name(&f("environment.json", "one")));
        assert_ne!(a, file_secret_name(&f("environment.json", "two")));
        assert!(a.starts_with("seed-env-") && a.len() == "seed-env-".len() + 12);
        assert!(file_secret_name(&f(DEV_STORE_FILE, "x")).starts_with("seed-dev-"));
    }

    #[test]
    fn script_creates_nested_dirs_and_checks_digests() {
        let s = init_script(&[f("environment.json", "{}"), f(DEV_STORE_FILE, "k=v")]).unwrap();
        assert!(s.starts_with("set -eu\numask 022\n"));
        assert!(
            s.contains("printf '%s' \"$GREENTIC_SEED_ENVIRONMENT_JSON\" > /seed/environment.json")
        );
        assert!(s.contains("mkdir -p /seed/.greentic/dev\n"));
        assert!(s.contains("GREENTIC_SEED_DEV_STORE_SHA256") && s.contains("sha256sum -c -s"));
    }

    #[test]
    fn unsafe_names_and_collisions_are_refused() {
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a//b",
            "a b",
            "a;rm",
            "a$(id)",
            "a/",
        ] {
            assert!(init_script(&[f(bad, "x")]).is_err(), "{bad:?}");
        }
        assert!(matches!(
            init_script(&[f("a.b", "x"), f("a_b", "y")]),
            Err(SeedError::Collision { .. })
        ));
    }

    #[test]
    fn debug_never_prints_content() {
        assert!(!format!("{:?}", f("environment.json", "TOPSECRET")).contains("TOPSECRET"));
    }
}
