//! Pure description of the `seed-init` container (ungated, no AWS types).
//!
//! Decision record: `docs/aws-ecs-seed-and-bundle-delivery.md` section 3.
//!
//! The warm path (always compiled) needs only [`SEED_INIT_IMAGE`]; the
//! container-rendering items are read by the `deploy-aws-ecs` real target, so
//! they are compiled with it (and for tests) rather than carried dead in a
//! `creds-aws`-only build.

#[cfg(any(test, feature = "deploy-aws-ecs"))]
use super::deploy_target::SeedFile;

#[cfg(any(test, feature = "deploy-aws-ecs"))]
/// Container name of the init container; the worker `dependsOn` it.
pub(crate) const SEED_INIT_CONTAINER: &str = "seed-init";
#[cfg(any(test, feature = "deploy-aws-ecs"))]
/// Name of the task-level bind-mount volume shared by both containers.
pub(crate) const SEED_VOLUME: &str = "seed";
/// Busybox init image, pinned by index digest (decision record 3.3).
pub(crate) const SEED_INIT_IMAGE: &str = "public.ecr.aws/docker/library/busybox:1.37.0-musl@sha256:5cec3fc171c87218698e85a52af7087de727372aae264a787b8112901a5b0092";

#[cfg(any(test, feature = "deploy-aws-ecs"))]
/// Env var carrying the file's content (injected from Secrets Manager).
pub(crate) fn content_var(file: &SeedFile) -> String {
    format!("GREENTIC_SEED_{}", var_stem(&file.name))
}

#[cfg(any(test, feature = "deploy-aws-ecs"))]
/// Env var carrying the file's expected SHA-256 (plain, a digest is public).
pub(crate) fn sha_var(file: &SeedFile) -> String {
    format!("{}_SHA256", content_var(file))
}

#[cfg(any(test, feature = "deploy-aws-ecs"))]
fn var_stem(name: &str) -> String {
    match name {
        "environment.json" => "ENVIRONMENT_JSON".to_string(),
        ".greentic/dev/.dev.secrets.env" => "DEV_STORE".to_string(),
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

#[cfg(any(test, feature = "deploy-aws-ecs"))]
/// A seed file name the init script cannot safely embed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum SeedNameError {
    /// Empty, absolute, containing a `.`/`..`/empty path component, or a
    /// character outside `[A-Za-z0-9._/-]` (names go into a shell script).
    #[error(
        "seed file name {0:?} is not allowed (use [A-Za-z0-9._/-], no leading `/`, no `.`/`..`/empty components)"
    )]
    Invalid(String),
    /// Two files would share one environment variable.
    #[error("seed files {first:?} and {second:?} map to the same env var `{var}`")]
    Collision {
        first: String,
        second: String,
        var: String,
    },
}

#[cfg(any(test, feature = "deploy-aws-ecs"))]
fn validate_name(name: &str) -> Result<(), SeedNameError> {
    let bad = name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
        || name
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..");
    if bad {
        Err(SeedNameError::Invalid(name.to_string()))
    } else {
        Ok(())
    }
}

#[cfg(any(test, feature = "deploy-aws-ecs"))]
/// The `sh -c` script: write each file byte for byte, then verify its digest.
/// Fails closed on a name that is unsafe to embed or collides on its env var.
pub(crate) fn script(files: &[SeedFile]) -> Result<String, SeedNameError> {
    let mut seen: Vec<(String, &str)> = Vec::with_capacity(files.len());
    for f in files {
        validate_name(&f.name)?;
        let stem = var_stem(&f.name);
        if let Some((_, first)) = seen.iter().find(|(s, _)| *s == stem) {
            return Err(SeedNameError::Collision {
                first: (*first).to_string(),
                second: f.name.clone(),
                var: content_var(f),
            });
        }
        seen.push((stem, &f.name));
    }
    let mut out = String::from("set -eu\numask 022\n");
    for f in files {
        let path = format!("/seed/{}", f.name);
        if let Some((dir, _)) = f.name.rsplit_once('/') {
            out.push_str(&format!("mkdir -p /seed/{dir}\n"));
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

    fn file(name: &str) -> SeedFile {
        SeedFile {
            name: name.to_string(),
            secret_value_from: "arn:x:::v1".to_string(),
            sha256_hex: "ab".repeat(32),
        }
    }

    #[test]
    fn var_names_follow_the_decision_record() {
        assert_eq!(
            content_var(&file("environment.json")),
            "GREENTIC_SEED_ENVIRONMENT_JSON"
        );
        assert_eq!(
            sha_var(&file(".greentic/dev/.dev.secrets.env")),
            "GREENTIC_SEED_DEV_STORE_SHA256"
        );
    }

    #[test]
    fn script_writes_then_verifies_each_file() {
        let s = script(&[
            file("environment.json"),
            file(".greentic/dev/.dev.secrets.env"),
        ])
        .unwrap();
        assert!(s.starts_with("set -eu\numask 022\n"));
        assert!(s.contains(
            "printf '%s' \"$GREENTIC_SEED_ENVIRONMENT_JSON\" > /seed/environment.json\n"
        ));
        assert!(s.contains("mkdir -p /seed/.greentic/dev\n"));
        assert!(s.contains("sha256sum -c -s"));
    }

    #[test]
    fn seed_file_names_are_validated() {
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../b",
            "a/./b",
            "a//b",
            "a b",
            "a;rm -rf x",
            "a$(id)",
            "a'b",
            "a\nb",
            "a/",
        ] {
            assert!(
                script(&[file(bad)]).is_err(),
                "name {bad:?} must be refused"
            );
        }
        assert!(script(&[file("environment.json")]).is_ok());
        assert!(script(&[file(".greentic/dev/.dev.secrets.env")]).is_ok());
    }

    #[test]
    fn colliding_seed_var_stems_are_refused() {
        // `a.b` and `a_b` both map to GREENTIC_SEED_A_B.
        match script(&[file("a.b"), file("a_b")]) {
            Err(SeedNameError::Collision { .. }) => {}
            other => panic!("expected a collision, got {other:?}"),
        }
    }
}
