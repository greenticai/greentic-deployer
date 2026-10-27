//! Pure description of the `seed-init` container (ungated, no AWS types).
//!
//! Decision record: `docs/aws-ecs-seed-and-bundle-delivery.md` section 3.

// Consumed by the warm path in a later phase-1 task; until then only tests and
// the gated real target reference these items.
#![allow(dead_code)]

use super::deploy_target::SeedFile;

/// Container name of the init container; the worker `dependsOn` it.
pub(crate) const SEED_INIT_CONTAINER: &str = "seed-init";
/// Name of the task-level bind-mount volume shared by both containers.
pub(crate) const SEED_VOLUME: &str = "seed";
/// Busybox init image, pinned by index digest (decision record 3.3).
pub(crate) const SEED_INIT_IMAGE: &str = "public.ecr.aws/docker/library/busybox:1.37.0-musl@sha256:5cec3fc171c87218698e85a52af7087de727372aae264a787b8112901a5b0092";

/// Env var carrying the file's content (injected from Secrets Manager).
pub(crate) fn content_var(file: &SeedFile) -> String {
    format!("GREENTIC_SEED_{}", var_stem(&file.name))
}

/// Env var carrying the file's expected SHA-256 (plain, a digest is public).
pub(crate) fn sha_var(file: &SeedFile) -> String {
    format!("{}_SHA256", content_var(file))
}

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

/// The `sh -c` script: write each file byte for byte, then verify its digest.
pub(crate) fn script(files: &[SeedFile]) -> String {
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
    out
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
        ]);
        assert!(s.starts_with("set -eu\numask 022\n"));
        assert!(s.contains(
            "printf '%s' \"$GREENTIC_SEED_ENVIRONMENT_JSON\" > /seed/environment.json\n"
        ));
        assert!(s.contains("mkdir -p /seed/.greentic/dev\n"));
        assert!(s.contains("sha256sum -c -s"));
    }
}
