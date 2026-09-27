//! Pure builders for a SoR unit's Cloud Run service. No I/O; unit-tested.

use std::time::Duration;

use super::target::{ArRepository, SorServiceLabels, SorServiceRef, SorServiceSpec};
use crate::env_packs::gcp_cloudrun::deploy_target::{
    ScalingSpec, SecretEnvVar, SecretMount, SecretMountItem,
};
use crate::env_packs::k8s::manifests::sor::{
    SOR_ANSWERS_KEY, SOR_PORT, SOR_POSTGRES_URL_KEY, SOR_SHARED_SECRET_KEY, SorUnitInputs,
    sor_inputs_hash,
};
use crate::environment::sor_units::{CloudRunSorPlacement, SorUnit};
use crate::runtime_secrets::SecretValue;

/// Startup probe path. The probe reaches the container directly; Google's
/// front end swallows `/healthz` only for EXTERNAL requests to `*.run.app`.
pub const SOR_HEALTH_PATH: &str = "/healthz";
pub const SOR_CA_MOUNT_DIR: &str = "/etc/sorx/postgres-ca";
pub const SOR_CA_FILE: &str = "ca.pem";
pub const SOR_CA_FILE_ENV: &str = "SORX_POSTGRES_CA_FILE";
/// Cloud Run's root filesystem is read-only except `/tmp`; sorx writes under
/// `$HOME/.config`.
const SOR_RUNTIME_HOME: &str = "/tmp";
pub const SOR_READY_TIMEOUT_ENV: &str = "GREENTIC_GCP_SOR_READY_TIMEOUT_SECS";
const SOR_READY_TIMEOUT: Duration = Duration::from_secs(300);
const SOR_READY_POLL_INTERVAL: Duration = Duration::from_secs(5);
const AR_HOST_SUFFIX: &str = "-docker.pkg.dev";
pub const AR_READER_ROLE: &str = "roles/artifactregistry.reader";

/// How long a SoR service may take to become ready (pack pull + Postgres
/// connect at boot) and how often to ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SorReadyTiming {
    pub timeout: Duration,
    pub poll: Duration,
}

impl SorReadyTiming {
    pub fn from_env() -> Self {
        Self::from_override(std::env::var(SOR_READY_TIMEOUT_ENV).ok().as_deref())
    }

    fn from_override(value: Option<&str>) -> Self {
        let timeout = value
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(SOR_READY_TIMEOUT);
        Self {
            timeout,
            poll: SOR_READY_POLL_INTERVAL,
        }
    }
}

/// E3: scale to zero, never more than one instance.
pub fn sor_scaling() -> ScalingSpec {
    ScalingSpec {
        cpu: "1".to_string(),
        memory: "512Mi".to_string(),
        min_instances: 0,
        max_instances: 1,
        concurrency: 80,
    }
}

pub fn sor_args(pack_ref: &str) -> Vec<String> {
    vec![
        "start".to_string(),
        pack_ref.to_string(),
        "--answers".to_string(),
        format!("env:{SOR_ANSWERS_KEY}"),
        "--non-interactive".to_string(),
    ]
}

pub fn sor_service_ref(placement: &CloudRunSorPlacement) -> SorServiceRef {
    SorServiceRef {
        project: placement.project.clone(),
        region: placement.region.clone(),
        name: placement.service.clone(),
    }
}

/// What a deploy of this unit INTENDS, computable before staging so a re-run
/// with unchanged inputs mints no secret versions and no revision. Covers the
/// image, the pack, the runtime identity, a digest of every input, the secret
/// name and the fixed service shape. Length-prefixed fields; 32 hex chars (a
/// valid GCP label value). Not reversible to any input: the inputs hash
/// includes the high-entropy shared secret.
pub fn sor_intent(
    unit: &SorUnit,
    inputs: &SorUnitInputs,
    runtime_service_account: &str,
    placement: &CloudRunSorPlacement,
) -> String {
    use sha2::{Digest, Sha256};
    let scaling = sor_scaling();
    let mut hasher = Sha256::new();
    let mut field = |bytes: &[u8]| {
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    };
    field(unit.image.as_bytes());
    field(unit.pack_ref.as_bytes());
    field(runtime_service_account.as_bytes());
    field(sor_inputs_hash(inputs).as_bytes());
    field(placement.secret.as_bytes());
    field(&SOR_PORT.to_le_bytes());
    field(SOR_HEALTH_PATH.as_bytes());
    field(scaling.cpu.as_bytes());
    field(scaling.memory.as_bytes());
    field(&scaling.min_instances.to_le_bytes());
    field(&scaling.max_instances.to_le_bytes());
    field(&scaling.concurrency.to_le_bytes());
    hex::encode(&hasher.finalize()[..16])
}

/// The Secret Manager versions one staging produced (numbers, never values).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedVersions {
    pub answers: String,
    pub postgres_url: String,
    pub shared_secret: String,
    pub postgres_ca: Option<String>,
}

pub struct SorServiceInputs<'a> {
    pub unit: &'a SorUnit,
    pub placement: &'a CloudRunSorPlacement,
    pub runtime_service_account: &'a str,
    pub owner: &'a str,
    pub intent: &'a str,
    pub staged: &'a StagedVersions,
}

/// The same env/file contract as the k8s pod, on Cloud Run primitives.
pub fn sor_service_spec(i: &SorServiceInputs<'_>) -> SorServiceSpec {
    let secret = &i.placement.secret;
    let from_secret = |name: &str, version: &str| SecretEnvVar {
        name: name.to_string(),
        secret_name: secret.clone(),
        version: version.to_string(),
    };
    let mut env = vec![("HOME".to_string(), SOR_RUNTIME_HOME.to_string())];
    let mut secret_mounts = Vec::new();
    if let Some(ca_version) = &i.staged.postgres_ca {
        env.push((
            SOR_CA_FILE_ENV.to_string(),
            format!("{SOR_CA_MOUNT_DIR}/{SOR_CA_FILE}"),
        ));
        secret_mounts.push(SecretMount {
            mount_dir: SOR_CA_MOUNT_DIR.to_string(),
            secret_name: secret.clone(),
            items: vec![SecretMountItem {
                version: ca_version.clone(),
                rel_path: SOR_CA_FILE.to_string(),
            }],
        });
    }
    SorServiceSpec {
        service: sor_service_ref(i.placement),
        image: i.unit.image.clone(),
        args: sor_args(&i.unit.pack_ref),
        port: SOR_PORT,
        runtime_service_account: i.runtime_service_account.to_string(),
        env,
        secret_env: vec![
            from_secret(SOR_ANSWERS_KEY, &i.staged.answers),
            from_secret(SOR_POSTGRES_URL_KEY, &i.staged.postgres_url),
            from_secret(SOR_SHARED_SECRET_KEY, &i.staged.shared_secret),
        ],
        secret_mounts,
        scaling: sor_scaling(),
        health_path: SOR_HEALTH_PATH.to_string(),
        labels: SorServiceLabels {
            owner: i.owner.to_string(),
            unit_id: i.unit.unit_id.clone(),
            intent: i.intent.to_string(),
        },
    }
}

/// Contract C1 on Cloud Run: `{url, token, tenant}` with the service's public
/// URL. A [`SecretValue`] because it carries the shared secret.
pub fn cloud_run_route_document(unit: &SorUnit, inputs: &SorUnitInputs, url: &str) -> SecretValue {
    SecretValue::from(
        serde_json::json!({
            "url": url.trim_end_matches('/'),
            "token": inputs.shared_secret.expose(),
            "tenant": unit.tenant_id,
        })
        .to_string(),
    )
}

/// The Artifact Registry repository a pack lives in, or `None` for any other
/// registry (which sorx must then pull anonymously).
pub fn ar_repository(pack_ref: &str) -> Option<ArRepository> {
    let rest = pack_ref.strip_prefix("oci://")?;
    let (host, path) = rest.split_once('/')?;
    let location = host
        .strip_suffix(AR_HOST_SUFFIX)
        .filter(|l| !l.is_empty())?;
    let mut segments = path.split('/');
    let project = segments.next().filter(|s| !s.is_empty())?;
    let repository = segments
        .next()?
        .split(['@', ':'])
        .next()
        .filter(|s| !s.is_empty())?;
    Some(ArRepository {
        project: project.to_string(),
        location: location.to_string(),
        repository: repository.to_string(),
    })
}

/// What an operator runs when the deployer may not write the binding itself.
pub fn ar_reader_remediation(repo: &ArRepository, service_account: &str) -> String {
    format!(
        "gcloud artifacts repositories add-iam-policy-binding {} --location={} --project={} \
         --member='serviceAccount:{service_account}' --role={AR_READER_ROLE}",
        repo.repository, repo.location, repo.project
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env_packs::k8s::manifests::sor::tests::{inputs, unit};

    fn placement() -> CloudRunSorPlacement {
        CloudRunSorPlacement::for_unit("proj", "europe-west1", "gtc-local", "landlord")
    }

    fn staged(with_ca: bool) -> StagedVersions {
        StagedVersions {
            answers: "1".into(),
            postgres_url: "2".into(),
            shared_secret: "3".into(),
            postgres_ca: with_ca.then(|| "4".to_string()),
        }
    }

    fn built(with_ca: bool) -> SorServiceSpec {
        let (u, p, s) = (unit(), placement(), staged(with_ca));
        sor_service_spec(&SorServiceInputs {
            unit: &u,
            placement: &p,
            runtime_service_account: "sa@proj.iam.gserviceaccount.com",
            owner: "local-stamp",
            intent: "0123456789abcdef0123456789abcdef",
            staged: &s,
        })
    }

    #[test]
    fn the_service_runs_sorx_non_interactively_from_the_pinned_pack_on_8787() {
        let spec = built(false);
        assert_eq!(spec.service.name, "gtc-sor-landlord");
        assert_eq!(spec.service.region, "europe-west1");
        assert_eq!(spec.image, unit().image);
        assert_eq!(
            spec.args,
            vec![
                "start".to_string(),
                unit().pack_ref,
                "--answers".into(),
                "env:SORX_ANSWERS".into(),
                "--non-interactive".into(),
            ]
        );
        assert_eq!(spec.port, 8787);
        assert_eq!(spec.health_path, "/healthz");
        assert_eq!(
            (spec.scaling.min_instances, spec.scaling.max_instances),
            (0, 1)
        );
        assert_eq!(
            spec.runtime_service_account,
            "sa@proj.iam.gserviceaccount.com"
        );
        assert_eq!(spec.env, vec![("HOME".to_string(), "/tmp".to_string())]);
    }

    #[test]
    fn every_input_arrives_through_a_version_pinned_secret_and_no_value_is_in_the_spec() {
        let spec = built(true);
        let refs: Vec<(&str, &str, &str)> = spec
            .secret_env
            .iter()
            .map(|e| (e.name.as_str(), e.secret_name.as_str(), e.version.as_str()))
            .collect();
        assert_eq!(
            refs,
            vec![
                ("SORX_ANSWERS", "gtc-local-sor-landlord", "1"),
                ("SORX_POSTGRES_URL", "gtc-local-sor-landlord", "2"),
                ("SORX_SHARED_SECRET", "gtc-local-sor-landlord", "3"),
            ]
        );
        let debug = format!("{spec:?}");
        assert!(
            !debug.contains("SECRET-"),
            "no input value in the spec: {debug}"
        );
        assert!(!debug.contains("postgres://"), "{debug}");
    }

    #[test]
    fn the_ca_is_a_mounted_file_only_when_declared() {
        assert!(built(false).secret_mounts.is_empty());
        let spec = built(true);
        assert_eq!(spec.secret_mounts.len(), 1);
        let mount = &spec.secret_mounts[0];
        assert_eq!(mount.mount_dir, "/etc/sorx/postgres-ca");
        assert_eq!(mount.secret_name, "gtc-local-sor-landlord");
        assert_eq!(mount.items.len(), 1);
        assert_eq!(mount.items[0].version, "4");
        assert_eq!(mount.items[0].rel_path, "ca.pem");
        assert!(spec.env.contains(&(
            "SORX_POSTGRES_CA_FILE".to_string(),
            "/etc/sorx/postgres-ca/ca.pem".to_string()
        )));
    }

    #[test]
    fn the_intent_moves_with_every_input_and_nothing_else() {
        let (u, p) = (unit(), placement());
        let base = sor_intent(&u, &inputs(false), "sa", &p);
        assert_eq!(base.len(), 32);
        assert!(
            base.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_eq!(
            base,
            sor_intent(&u, &inputs(false), "sa", &p),
            "deterministic"
        );

        let mut rotated = inputs(false);
        rotated.shared_secret = SecretValue::from("rotated".to_string());
        assert_ne!(base, sor_intent(&u, &rotated, "sa", &p));
        assert_ne!(base, sor_intent(&u, &inputs(true), "sa", &p));
        assert_ne!(base, sor_intent(&u, &inputs(false), "other-sa", &p));
        let mut moved_image = unit();
        moved_image.image = "ghcr.io/greenticai/greentic-sorx:next".into();
        assert_ne!(base, sor_intent(&moved_image, &inputs(false), "sa", &p));
        let other_secret = CloudRunSorPlacement::for_unit("proj", "europe-west1", "x", "landlord");
        assert_ne!(base, sor_intent(&u, &inputs(false), "sa", &other_secret));
    }

    #[test]
    fn the_route_document_carries_the_run_app_url_without_a_trailing_slash() {
        let doc = cloud_run_route_document(
            &unit(),
            &inputs(false),
            "https://gtc-sor-landlord-abc123-ew.a.run.app/",
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(doc.expose()).unwrap(),
            serde_json::json!({
                "url": "https://gtc-sor-landlord-abc123-ew.a.run.app",
                "token": "shared-SECRET-token",
                "tenant": "acme",
            })
        );
        assert_eq!(format!("{doc:?}"), "<redacted>");
        assert!(!format!("{doc:?}").contains("shared-SECRET-token"));
    }

    #[test]
    fn an_artifact_registry_pack_names_its_repository_and_other_registries_name_none() {
        let hex = "d".repeat(64);
        assert_eq!(
            ar_repository(&format!(
                "oci://europe-west1-docker.pkg.dev/proj/greentic/sorla/landlord:t1@sha256:{hex}"
            )),
            Some(ArRepository {
                project: "proj".into(),
                location: "europe-west1".into(),
                repository: "greentic".into(),
            })
        );
        assert_eq!(
            ar_repository(&format!(
                "oci://europe-west1-docker.pkg.dev/proj/greentic@sha256:{hex}"
            )),
            Some(ArRepository {
                project: "proj".into(),
                location: "europe-west1".into(),
                repository: "greentic".into(),
            })
        );
        assert_eq!(
            ar_repository(&format!("oci://ghcr.io/greenticai/sor@sha256:{hex}")),
            None
        );
        assert_eq!(
            ar_repository(&format!("oci://-docker.pkg.dev/proj/r@sha256:{hex}")),
            None
        );
        assert_eq!(ar_repository("not-oci"), None);
    }

    #[test]
    fn the_remediation_is_the_gcloud_command_for_that_repository_and_account() {
        let repo = ArRepository {
            project: "proj".into(),
            location: "europe-west1".into(),
            repository: "greentic".into(),
        };
        assert_eq!(
            ar_reader_remediation(&repo, "sa@proj.iam.gserviceaccount.com"),
            "gcloud artifacts repositories add-iam-policy-binding greentic \
             --location=europe-west1 --project=proj \
             --member='serviceAccount:sa@proj.iam.gserviceaccount.com' \
             --role=roles/artifactregistry.reader"
        );
    }

    #[test]
    fn the_ready_timeout_reads_its_override_and_ignores_garbage() {
        assert_eq!(SorReadyTiming::from_override(None).timeout.as_secs(), 300);
        assert_eq!(
            SorReadyTiming::from_override(Some(" 600 "))
                .timeout
                .as_secs(),
            600
        );
        assert_eq!(
            SorReadyTiming::from_override(Some("soon"))
                .timeout
                .as_secs(),
            300
        );
        assert_eq!(SorReadyTiming::from_override(None).poll.as_secs(), 5);
    }
}
