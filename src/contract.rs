use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::Read;
use std::path::Path;

use greentic_types::pack_manifest::{ExtensionInline, ExtensionRef, PackManifest};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::Provider;
use crate::error::{DeployerError, Result};
use crate::pack_introspect::read_entry_from_gtpack;

pub const EXT_DEPLOYER_V1: &str = "greentic.deployer.v1";
pub const EXT_DEPLOY_AWS: &str = "greentic.deploy-aws";
pub const EXT_DEPLOY_AZURE: &str = "greentic.deploy-azure";
pub const EXT_DEPLOY_GCP: &str = "greentic.deploy-gcp";
pub const DEFAULT_GHCR_OPERATOR_IMAGE: &str = "ghcr.io/greenticai/greentic-start-distroless@sha256:6287eafd5f54b6be400e9d19f87791866dd23d8e0a71d1a5fdde7604d842edc8";
pub const DEFAULT_GCP_OPERATOR_IMAGE: &str = "europe-west1-docker.pkg.dev/x-plateau-483512-p6/greentic-images/greentic-start-distroless@sha256:5f7e4b70271c09b2a099e2c6d5c8641cbdb5a20698dcbba0e3b0f90a0f3e0e48";
pub const DEFAULT_OPERATOR_IMAGE_DIGEST: &str =
    "sha256:6287eafd5f54b6be400e9d19f87791866dd23d8e0a71d1a5fdde7604d842edc8";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeployerCapability {
    Generate,
    Plan,
    Apply,
    Destroy,
    Status,
    Rollback,
}

impl DeployerCapability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Generate => "generate",
            Self::Plan => "plan",
            Self::Apply => "apply",
            Self::Destroy => "destroy",
            Self::Status => "status",
            Self::Rollback => "rollback",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudCredentialKind {
    AwsAccessKey,
    AwsProfile,
    AwsWebIdentity,
    AzureClientSecret,
    AzureOidc,
    GcpApplicationCredentials,
    GcpAccessToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptFieldKindV1 {
    Required,
    Optional,
    Secret,
    OptionalSecret,
    Static,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptFieldSpecV1 {
    pub env_name: String,
    pub prompt: String,
    pub kind: PromptFieldKindV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRequirementV1 {
    pub kind: CloudCredentialKind,
    pub label: String,
    pub env_vars: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub satisfaction_env_groups: Vec<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prompt_fields: Vec<PromptFieldSpecV1>,
    pub help: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariableRequirementV1 {
    pub name: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudTargetRequirementsV1 {
    pub target: String,
    pub target_label: String,
    pub provider_pack_filename: String,
    pub remote_bundle_source_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_bundle_source_help: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub informational_notes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_requirements: Vec<CredentialRequirementV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub variable_requirements: Vec<VariableRequirementV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudDeployerExtensionDescriptorV1 {
    pub extension_id: String,
    pub extension_version: String,
    pub provider: String,
    pub deployer_pack_id: String,
    pub provider_pack_filename: String,
    pub target_id: String,
}

impl CloudTargetRequirementsV1 {
    pub fn aws() -> Self {
        Self {
            target: "aws".to_string(),
            target_label: "AWS".to_string(),
            provider_pack_filename: "aws.gtpack".to_string(),
            remote_bundle_source_required: true,
            remote_bundle_source_help: Some(
                "Pass --deploy-bundle-source https://.../bundle.gtbundle or set GREENTIC_DEPLOY_BUNDLE_SOURCE"
                    .to_string(),
            ),
            informational_notes: vec!["Internal AWS bootstrap now handles admin TLS server secrets"
                .to_string()],
            credential_requirements: vec![
                CredentialRequirementV1 {
                    kind: CloudCredentialKind::AwsAccessKey,
                    label: "Access key pair".to_string(),
                    env_vars: vec![
                        "AWS_ACCESS_KEY_ID".to_string(),
                        "AWS_SECRET_ACCESS_KEY".to_string(),
                    ],
                    satisfaction_env_groups: vec![vec![
                        "AWS_ACCESS_KEY_ID".to_string(),
                        "AWS_SECRET_ACCESS_KEY".to_string(),
                    ]],
                    prompt_fields: vec![
                        PromptFieldSpecV1 {
                            env_name: "AWS_ACCESS_KEY_ID".to_string(),
                            prompt: "AWS access key ID:".to_string(),
                            kind: PromptFieldKindV1::Required,
                            static_value: None,
                        },
                        PromptFieldSpecV1 {
                            env_name: "AWS_SECRET_ACCESS_KEY".to_string(),
                            prompt: "AWS secret access key:".to_string(),
                            kind: PromptFieldKindV1::Secret,
                            static_value: None,
                        },
                        PromptFieldSpecV1 {
                            env_name: "AWS_SESSION_TOKEN".to_string(),
                            prompt: "AWS session token (optional):".to_string(),
                            kind: PromptFieldKindV1::OptionalSecret,
                            static_value: None,
                        },
                        PromptFieldSpecV1 {
                            env_name: "AWS_DEFAULT_REGION".to_string(),
                            prompt: "AWS default region:".to_string(),
                            kind: PromptFieldKindV1::Static,
                            static_value: Some("eu-north-1".to_string()),
                        },
                    ],
                    help: "AWS access key credentials".to_string(),
                },
                CredentialRequirementV1 {
                    kind: CloudCredentialKind::AwsProfile,
                    env_vars: vec!["AWS_PROFILE".to_string(), "AWS_DEFAULT_PROFILE".to_string()],
                    label: "AWS profile".to_string(),
                    satisfaction_env_groups: vec![
                        vec!["AWS_PROFILE".to_string()],
                        vec!["AWS_DEFAULT_PROFILE".to_string()],
                    ],
                    prompt_fields: vec![
                        PromptFieldSpecV1 {
                            env_name: "AWS_PROFILE".to_string(),
                            prompt: "AWS profile:".to_string(),
                            kind: PromptFieldKindV1::Required,
                            static_value: None,
                        },
                        PromptFieldSpecV1 {
                            env_name: "AWS_DEFAULT_REGION".to_string(),
                            prompt: "AWS default region:".to_string(),
                            kind: PromptFieldKindV1::Static,
                            static_value: Some("eu-north-1".to_string()),
                        },
                    ],
                    help: "AWS shared profile credentials".to_string(),
                },
                CredentialRequirementV1 {
                    kind: CloudCredentialKind::AwsWebIdentity,
                    label: "Web identity token file".to_string(),
                    env_vars: vec!["AWS_WEB_IDENTITY_TOKEN_FILE".to_string()],
                    satisfaction_env_groups: vec![vec!["AWS_WEB_IDENTITY_TOKEN_FILE".to_string()]],
                    prompt_fields: vec![
                        PromptFieldSpecV1 {
                            env_name: "AWS_WEB_IDENTITY_TOKEN_FILE".to_string(),
                            prompt: "AWS web identity token file:".to_string(),
                            kind: PromptFieldKindV1::Required,
                            static_value: None,
                        },
                        PromptFieldSpecV1 {
                            env_name: "AWS_ROLE_ARN".to_string(),
                            prompt: "AWS role ARN (optional):".to_string(),
                            kind: PromptFieldKindV1::Optional,
                            static_value: None,
                        },
                    ],
                    help: "AWS web identity credentials".to_string(),
                },
            ],
            variable_requirements: vec![
                VariableRequirementV1 {
                    name: "GREENTIC_DEPLOY_TERRAFORM_VAR_REMOTE_STATE_BACKEND".to_string(),
                    required: true,
                    prompt: Some("Terraform remote state backend:".to_string()),
                    default_value: Some("s3".to_string()),
                    description: Some("Terraform remote state backend".to_string()),
                },
                VariableRequirementV1 {
                    name: "GREENTIC_DEPLOY_TERRAFORM_VAR_OPERATOR_IMAGE".to_string(),
                    required: false,
                    prompt: None,
                    default_value: Some(DEFAULT_GHCR_OPERATOR_IMAGE.to_string()),
                    description: Some("Optional operator image override".to_string()),
                },
                VariableRequirementV1 {
                    name: "GREENTIC_DEPLOY_TERRAFORM_VAR_OPERATOR_IMAGE_DIGEST".to_string(),
                    required: false,
                    prompt: None,
                    default_value: Some(DEFAULT_OPERATOR_IMAGE_DIGEST.to_string()),
                    description: Some("Optional operator image digest override".to_string()),
                },
                VariableRequirementV1 {
                    name: "GREENTIC_DEPLOY_TERRAFORM_VAR_REDIS_URL".to_string(),
                    required: false,
                    prompt: Some(
                        "Shared Redis URL (recommended for cloud webchat/state):".to_string(),
                    ),
                    default_value: None,
                    description: Some(
                        "Optional shared Redis URL for multi-instance state (for example redis://host:6379/0)"
                            .to_string(),
                    ),
                },
                VariableRequirementV1 {
                    name: "GREENTIC_DEPLOY_TERRAFORM_VAR_DNS_NAME".to_string(),
                    required: false,
                    prompt: None,
                    default_value: None,
                    description: Some("Optional personalized DNS name".to_string()),
                },
            ],
        }
    }

    pub fn azure() -> Self {
        Self {
            target: "azure".to_string(),
            target_label: "Azure".to_string(),
            provider_pack_filename: "azure.gtpack".to_string(),
            remote_bundle_source_required: true,
            remote_bundle_source_help: Some(
                "Pass --deploy-bundle-source https://.../bundle.gtbundle or set GREENTIC_DEPLOY_BUNDLE_SOURCE"
                    .to_string(),
            ),
            informational_notes: Vec::new(),
            credential_requirements: vec![
                CredentialRequirementV1 {
                    kind: CloudCredentialKind::AzureClientSecret,
                    label: "ARM service principal".to_string(),
                    env_vars: vec![
                        "ARM_CLIENT_ID".to_string(),
                        "ARM_TENANT_ID".to_string(),
                        "ARM_SUBSCRIPTION_ID".to_string(),
                    ],
                    satisfaction_env_groups: vec![vec![
                        "ARM_CLIENT_ID".to_string(),
                        "ARM_TENANT_ID".to_string(),
                        "ARM_SUBSCRIPTION_ID".to_string(),
                        "ARM_CLIENT_SECRET".to_string(),
                    ]],
                    prompt_fields: vec![
                        PromptFieldSpecV1 {
                            env_name: "ARM_SUBSCRIPTION_ID".to_string(),
                            prompt: "Azure subscription ID:".to_string(),
                            kind: PromptFieldKindV1::Required,
                            static_value: None,
                        },
                        PromptFieldSpecV1 {
                            env_name: "ARM_TENANT_ID".to_string(),
                            prompt: "Azure tenant ID:".to_string(),
                            kind: PromptFieldKindV1::Required,
                            static_value: None,
                        },
                        PromptFieldSpecV1 {
                            env_name: "ARM_CLIENT_ID".to_string(),
                            prompt: "Azure client ID:".to_string(),
                            kind: PromptFieldKindV1::Required,
                            static_value: None,
                        },
                        PromptFieldSpecV1 {
                            env_name: "ARM_CLIENT_SECRET".to_string(),
                            prompt: "Azure client secret:".to_string(),
                            kind: PromptFieldKindV1::Secret,
                            static_value: None,
                        },
                    ],
                    help: "Azure ARM client-secret style credentials".to_string(),
                },
                CredentialRequirementV1 {
                    kind: CloudCredentialKind::AzureOidc,
                    label: "Azure OIDC".to_string(),
                    env_vars: vec![
                        "ARM_USE_OIDC".to_string(),
                        "AZURE_CLIENT_ID".to_string(),
                        "AZURE_TENANT_ID".to_string(),
                        "AZURE_SUBSCRIPTION_ID".to_string(),
                    ],
                    satisfaction_env_groups: vec![
                        vec![
                            "ARM_CLIENT_ID".to_string(),
                            "ARM_TENANT_ID".to_string(),
                            "ARM_SUBSCRIPTION_ID".to_string(),
                            "ARM_USE_OIDC".to_string(),
                        ],
                        vec![
                            "AZURE_CLIENT_ID".to_string(),
                            "AZURE_TENANT_ID".to_string(),
                            "AZURE_SUBSCRIPTION_ID".to_string(),
                        ],
                    ],
                    prompt_fields: vec![
                        PromptFieldSpecV1 {
                            env_name: "ARM_SUBSCRIPTION_ID".to_string(),
                            prompt: "Azure subscription ID:".to_string(),
                            kind: PromptFieldKindV1::Required,
                            static_value: None,
                        },
                        PromptFieldSpecV1 {
                            env_name: "ARM_TENANT_ID".to_string(),
                            prompt: "Azure tenant ID:".to_string(),
                            kind: PromptFieldKindV1::Required,
                            static_value: None,
                        },
                        PromptFieldSpecV1 {
                            env_name: "ARM_CLIENT_ID".to_string(),
                            prompt: "Azure client ID:".to_string(),
                            kind: PromptFieldKindV1::Required,
                            static_value: None,
                        },
                        PromptFieldSpecV1 {
                            env_name: "ARM_USE_OIDC".to_string(),
                            prompt: String::new(),
                            kind: PromptFieldKindV1::Static,
                            static_value: Some("true".to_string()),
                        },
                    ],
                    help: "Azure OIDC credentials".to_string(),
                },
            ],
            variable_requirements: vec![
                VariableRequirementV1 {
                    name: "GREENTIC_DEPLOY_TERRAFORM_VAR_REMOTE_STATE_BACKEND".to_string(),
                    required: true,
                    prompt: Some("Terraform remote state backend:".to_string()),
                    default_value: Some("azurerm".to_string()),
                    description: Some("Terraform remote state backend".to_string()),
                },
                VariableRequirementV1 {
                    name: "GREENTIC_DEPLOY_TERRAFORM_VAR_AZURE_KEY_VAULT_ID".to_string(),
                    required: true,
                    prompt: Some("Azure Key Vault resource ID:".to_string()),
                    default_value: None,
                    description: Some("Azure Key Vault resource ID".to_string()),
                },
                VariableRequirementV1 {
                    name: "GREENTIC_DEPLOY_TERRAFORM_VAR_AZURE_LOCATION".to_string(),
                    required: true,
                    prompt: Some("Azure location:".to_string()),
                    default_value: Some("westeurope".to_string()),
                    description: Some("Azure location".to_string()),
                },
                VariableRequirementV1 {
                    name: "GREENTIC_DEPLOY_TERRAFORM_VAR_OPERATOR_IMAGE".to_string(),
                    required: false,
                    prompt: None,
                    default_value: Some(DEFAULT_GHCR_OPERATOR_IMAGE.to_string()),
                    description: Some("Optional operator image override".to_string()),
                },
                VariableRequirementV1 {
                    name: "GREENTIC_DEPLOY_TERRAFORM_VAR_OPERATOR_IMAGE_DIGEST".to_string(),
                    required: false,
                    prompt: None,
                    default_value: Some(DEFAULT_OPERATOR_IMAGE_DIGEST.to_string()),
                    description: Some("Optional operator image digest override".to_string()),
                },
            ],
        }
    }

    pub fn gcp() -> Self {
        Self {
            target: "gcp".to_string(),
            target_label: "GCP".to_string(),
            provider_pack_filename: "gcp.gtpack".to_string(),
            remote_bundle_source_required: true,
            remote_bundle_source_help: Some(
                "Pass --deploy-bundle-source https://.../bundle.gtbundle or set GREENTIC_DEPLOY_BUNDLE_SOURCE"
                    .to_string(),
            ),
            informational_notes: Vec::new(),
            credential_requirements: vec![
                CredentialRequirementV1 {
                    kind: CloudCredentialKind::GcpApplicationCredentials,
                    label: "Service account credentials file".to_string(),
                    env_vars: vec!["GOOGLE_APPLICATION_CREDENTIALS".to_string()],
                    satisfaction_env_groups: vec![vec![
                        "GOOGLE_APPLICATION_CREDENTIALS".to_string(),
                    ]],
                    prompt_fields: vec![PromptFieldSpecV1 {
                        env_name: "GOOGLE_APPLICATION_CREDENTIALS".to_string(),
                        prompt: "GOOGLE_APPLICATION_CREDENTIALS path:".to_string(),
                        kind: PromptFieldKindV1::Required,
                        static_value: None,
                    }],
                    help: "GCP application credentials JSON".to_string(),
                },
                CredentialRequirementV1 {
                    kind: CloudCredentialKind::GcpAccessToken,
                    label: "Access token".to_string(),
                    env_vars: vec![
                        "GOOGLE_OAUTH_ACCESS_TOKEN".to_string(),
                        "CLOUDSDK_AUTH_ACCESS_TOKEN".to_string(),
                    ],
                    satisfaction_env_groups: vec![
                        vec!["GOOGLE_OAUTH_ACCESS_TOKEN".to_string()],
                        vec!["CLOUDSDK_AUTH_ACCESS_TOKEN".to_string()],
                    ],
                    prompt_fields: vec![PromptFieldSpecV1 {
                        env_name: "CLOUDSDK_AUTH_ACCESS_TOKEN".to_string(),
                        prompt: "GCP access token:".to_string(),
                        kind: PromptFieldKindV1::Secret,
                        static_value: None,
                    }],
                    help: "GCP access token credentials".to_string(),
                },
            ],
            variable_requirements: vec![
                VariableRequirementV1 {
                    name: "GREENTIC_DEPLOY_TERRAFORM_VAR_REMOTE_STATE_BACKEND".to_string(),
                    required: true,
                    prompt: Some("Terraform remote state backend:".to_string()),
                    default_value: Some("gcs".to_string()),
                    description: Some("Terraform remote state backend".to_string()),
                },
                VariableRequirementV1 {
                    name: "GREENTIC_DEPLOY_TERRAFORM_VAR_GCP_PROJECT_ID".to_string(),
                    required: true,
                    prompt: Some("GCP project ID:".to_string()),
                    default_value: None,
                    description: Some("GCP project ID".to_string()),
                },
                VariableRequirementV1 {
                    name: "GREENTIC_DEPLOY_TERRAFORM_VAR_GCP_REGION".to_string(),
                    required: true,
                    prompt: Some("GCP region:".to_string()),
                    default_value: Some("us-central1".to_string()),
                    description: Some("GCP region".to_string()),
                },
                VariableRequirementV1 {
                    name: "GREENTIC_DEPLOY_TERRAFORM_VAR_OPERATOR_IMAGE".to_string(),
                    required: false,
                    prompt: None,
                    default_value: Some(DEFAULT_GCP_OPERATOR_IMAGE.to_string()),
                    description: Some("Optional operator image override".to_string()),
                },
                VariableRequirementV1 {
                    name: "GREENTIC_DEPLOY_TERRAFORM_VAR_OPERATOR_IMAGE_DIGEST".to_string(),
                    required: false,
                    prompt: None,
                    default_value: Some(DEFAULT_OPERATOR_IMAGE_DIGEST.to_string()),
                    description: Some("Optional operator image digest override".to_string()),
                },
            ],
        }
    }

    pub fn for_provider(provider: Provider) -> Option<Self> {
        let mut requirements = match provider {
            Provider::Aws => Some(Self::aws()),
            Provider::Azure => Some(Self::azure()),
            Provider::Gcp => Some(Self::gcp()),
            Provider::Local | Provider::K8s | Provider::Generic => None,
        }?;
        apply_operator_image_defaults_for_provider(&mut requirements, provider);
        Some(requirements)
    }
}

impl CloudDeployerExtensionDescriptorV1 {
    pub fn for_provider(provider: Provider) -> Option<Self> {
        let (extension_id, target_id, deployer_pack_id) = match provider {
            Provider::Aws => (
                EXT_DEPLOY_AWS,
                "aws-ecs-fargate-local",
                "greentic.deploy.aws",
            ),
            Provider::Azure => (
                EXT_DEPLOY_AZURE,
                "azure-container-apps-local",
                "greentic.deploy.azure",
            ),
            Provider::Gcp => (EXT_DEPLOY_GCP, "gcp-cloud-run-local", "greentic.deploy.gcp"),
            Provider::Local | Provider::K8s | Provider::Generic => return None,
        };
        let requirements = CloudTargetRequirementsV1::for_provider(provider)?;
        Some(Self {
            extension_id: extension_id.to_string(),
            extension_version: "0.1.0".to_string(),
            provider: provider.as_str().to_string(),
            deployer_pack_id: deployer_pack_id.to_string(),
            provider_pack_filename: requirements.provider_pack_filename,
            target_id: target_id.to_string(),
        })
    }
}

fn apply_operator_image_defaults_for_provider(
    requirements: &mut CloudTargetRequirementsV1,
    provider: Provider,
) {
    let operator_image_default = operator_image_default_for_provider(provider);
    for requirement in &mut requirements.variable_requirements {
        match requirement.name.as_str() {
            "GREENTIC_DEPLOY_TERRAFORM_VAR_OPERATOR_IMAGE" => {
                requirement.default_value = Some(operator_image_default.to_string());
            }
            "GREENTIC_DEPLOY_TERRAFORM_VAR_OPERATOR_IMAGE_DIGEST" => {
                requirement.default_value = Some(DEFAULT_OPERATOR_IMAGE_DIGEST.to_string());
            }
            _ => {}
        }
    }
}

fn operator_image_default_for_provider(provider: Provider) -> &'static str {
    match operator_image_source_for_provider(provider) {
        OperatorImageSource::Ghcr => DEFAULT_GHCR_OPERATOR_IMAGE,
        OperatorImageSource::GcpArtifactRegistry => DEFAULT_GCP_OPERATOR_IMAGE,
    }
}

fn operator_image_source_for_provider(provider: Provider) -> OperatorImageSource {
    let env_name = format!(
        "GREENTIC_DEPLOY_DEFAULT_OPERATOR_IMAGE_SOURCE_{}",
        provider.as_str().to_ascii_uppercase().replace('-', "_")
    );
    operator_image_source_for_provider_override(provider, non_empty_env_var(&env_name).as_deref())
}

fn operator_image_source_for_provider_override(
    provider: Provider,
    override_value: Option<&str>,
) -> OperatorImageSource {
    match override_value {
        Some("gcp-artifact-registry") => OperatorImageSource::GcpArtifactRegistry,
        Some("ghcr") => OperatorImageSource::Ghcr,
        _ if provider == Provider::Gcp => OperatorImageSource::GcpArtifactRegistry,
        _ => OperatorImageSource::Ghcr,
    }
}

fn non_empty_env_var(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperatorImageSource {
    Ghcr,
    GcpArtifactRegistry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployerContractV1 {
    pub schema_version: u32,
    pub planner: PlannerSpecV1,
    pub capabilities: Vec<CapabilitySpecV1>,
}

impl DeployerContractV1 {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(DeployerError::Contract(format!(
                "unsupported {} schema_version {}",
                EXT_DEPLOYER_V1, self.schema_version
            )));
        }
        self.planner.validate()?;

        let mut seen = BTreeSet::new();
        for capability in &self.capabilities {
            capability.validate()?;
            if !seen.insert(capability.capability) {
                return Err(DeployerError::Contract(format!(
                    "duplicate capability `{}` in {}",
                    capability.capability.as_str(),
                    EXT_DEPLOYER_V1
                )));
            }
        }

        if !seen.contains(&DeployerCapability::Plan) {
            return Err(DeployerError::Contract(format!(
                "{} must declare the `plan` capability",
                EXT_DEPLOYER_V1
            )));
        }

        Ok(())
    }

    pub fn capability(&self, capability: DeployerCapability) -> Option<&CapabilitySpecV1> {
        self.capabilities
            .iter()
            .find(|entry| entry.capability == capability)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannerSpecV1 {
    pub flow_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qa_spec_ref: Option<String>,
}

impl PlannerSpecV1 {
    fn validate(&self) -> Result<()> {
        if self.flow_id.trim().is_empty() {
            return Err(DeployerError::Contract(format!(
                "{} planner.flow_id must not be empty",
                EXT_DEPLOYER_V1
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySpecV1 {
    pub capability: DeployerCapability,
    pub flow_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_output_schema_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qa_spec_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub example_refs: Vec<String>,
}

impl CapabilitySpecV1 {
    fn validate(&self) -> Result<()> {
        if self.flow_id.trim().is_empty() {
            return Err(DeployerError::Contract(format!(
                "{} capability `{}` has empty flow_id",
                EXT_DEPLOYER_V1,
                self.capability.as_str()
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractAsset {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<JsonValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub size_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedCapabilityContract {
    pub capability: DeployerCapability,
    pub flow_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<ContractAsset>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<ContractAsset>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_output_schema: Option<ContractAsset>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qa_spec: Option<ContractAsset>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub examples: Vec<ContractAsset>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedPlannerContract {
    pub flow_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<ContractAsset>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<ContractAsset>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qa_spec: Option<ContractAsset>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedDeployerContract {
    pub schema_version: u32,
    pub planner: ResolvedPlannerContract,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<ResolvedCapabilityContract>,
}

pub fn get_deployer_contract_v1(manifest: &PackManifest) -> Result<Option<DeployerContractV1>> {
    let extension = manifest
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.get(EXT_DEPLOYER_V1));
    let inline = match extension.and_then(|entry| entry.inline.as_ref()) {
        Some(ExtensionInline::Other(value)) => value,
        Some(_) => {
            return Err(DeployerError::Contract(format!(
                "{} inline payload has unexpected type",
                EXT_DEPLOYER_V1
            )));
        }
        None => return Ok(None),
    };

    let payload: DeployerContractV1 = serde_json::from_value(inline.clone()).map_err(|err| {
        DeployerError::Contract(format!("{} deserialize failed: {}", EXT_DEPLOYER_V1, err))
    })?;
    payload.validate()?;
    Ok(Some(payload))
}

pub fn set_deployer_contract_v1(
    manifest: &mut PackManifest,
    contract: DeployerContractV1,
) -> Result<()> {
    contract.validate()?;
    let inline = serde_json::to_value(&contract).map_err(|err| {
        DeployerError::Contract(format!("{} serialize failed: {}", EXT_DEPLOYER_V1, err))
    })?;
    let extensions = manifest.extensions.get_or_insert_with(Default::default);
    extensions.insert(
        EXT_DEPLOYER_V1.to_string(),
        ExtensionRef {
            kind: EXT_DEPLOYER_V1.to_string(),
            version: "1.0.0".to_string(),
            digest: None,
            location: None,
            inline: Some(ExtensionInline::Other(inline)),
        },
    );
    Ok(())
}

pub fn set_cloud_deployer_extension_ref(
    manifest: &mut PackManifest,
    provider: Provider,
) -> Result<()> {
    let descriptor =
        CloudDeployerExtensionDescriptorV1::for_provider(provider).ok_or_else(|| {
            DeployerError::Contract(format!(
                "cloud deployer extension is not defined for provider {}",
                provider.as_str()
            ))
        })?;
    let inline = serde_json::to_value(&descriptor).map_err(|err| {
        DeployerError::Contract(format!(
            "{} serialize failed: {}",
            descriptor.extension_id, err
        ))
    })?;
    let extensions = manifest.extensions.get_or_insert_with(Default::default);
    extensions.insert(
        descriptor.extension_id.clone(),
        ExtensionRef {
            kind: descriptor.extension_id,
            version: descriptor.extension_version,
            digest: None,
            location: None,
            inline: Some(ExtensionInline::Other(inline)),
        },
    );
    Ok(())
}

pub fn read_pack_asset(pack_path: &Path, asset_ref: &str) -> Result<Vec<u8>> {
    let relative = Path::new(asset_ref);
    if relative.is_absolute() || asset_ref.contains("..") {
        return Err(DeployerError::Contract(format!(
            "pack asset ref must stay pack-relative: {}",
            asset_ref
        )));
    }

    if pack_path.is_dir() {
        return fs::read(pack_path.join(relative)).map_err(DeployerError::Io);
    }

    read_entry_from_gtpack(pack_path, relative)
}

pub fn copy_pack_subtree(
    pack_path: &Path,
    subtree_ref: &str,
    destination_root: &Path,
) -> Result<Vec<String>> {
    let subtree = Path::new(subtree_ref);
    if subtree.is_absolute() || subtree_ref.contains("..") {
        return Err(DeployerError::Contract(format!(
            "pack subtree ref must stay pack-relative: {}",
            subtree_ref
        )));
    }

    if pack_path.is_dir() {
        return copy_pack_subtree_from_dir(pack_path, subtree, destination_root);
    }

    copy_pack_subtree_from_gtpack(pack_path, subtree, destination_root)
}

fn copy_pack_subtree_from_dir(
    pack_root: &Path,
    subtree: &Path,
    destination_root: &Path,
) -> Result<Vec<String>> {
    let source_root = pack_root.join(subtree);
    if !source_root.exists() {
        return Ok(Vec::new());
    }

    let mut copied = Vec::new();
    copy_dir_recursive(&source_root, &source_root, destination_root, &mut copied)?;
    copied.sort();
    Ok(copied)
}

fn copy_dir_recursive(
    current: &Path,
    source_root: &Path,
    destination_root: &Path,
    copied: &mut Vec<String>,
) -> Result<()> {
    for entry in fs::read_dir(current).map_err(DeployerError::Io)? {
        let entry = entry.map_err(DeployerError::Io)?;
        let path = entry.path();
        if path.is_dir() {
            copy_dir_recursive(&path, source_root, destination_root, copied)?;
            continue;
        }

        let relative = path.strip_prefix(source_root).map_err(|err| {
            DeployerError::Contract(format!(
                "failed to relativize {} under {}: {}",
                path.display(),
                source_root.display(),
                err
            ))
        })?;
        let destination = destination_root.join(relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(DeployerError::Io)?;
        }
        fs::copy(&path, &destination).map_err(DeployerError::Io)?;
        copied.push(relative.display().to_string());
    }
    Ok(())
}

fn copy_pack_subtree_from_gtpack(
    pack_path: &Path,
    subtree: &Path,
    destination_root: &Path,
) -> Result<Vec<String>> {
    match copy_pack_subtree_from_tar_gtpack(pack_path, subtree, destination_root) {
        Ok(copied) => Ok(copied),
        Err(DeployerError::Io(err)) if err.kind() == std::io::ErrorKind::InvalidData => {
            copy_pack_subtree_from_zip_gtpack(pack_path, subtree, destination_root)
        }
        Err(DeployerError::Io(err)) if err.kind() == std::io::ErrorKind::Other => {
            copy_pack_subtree_from_zip_gtpack(pack_path, subtree, destination_root)
        }
        Err(err) => Err(err),
    }
}

fn copy_pack_subtree_from_tar_gtpack(
    pack_path: &Path,
    subtree: &Path,
    destination_root: &Path,
) -> Result<Vec<String>> {
    let file = fs::File::open(pack_path).map_err(DeployerError::Io)?;
    let mut archive = tar::Archive::new(file);
    let mut copied = Vec::new();

    for entry in archive.entries().map_err(DeployerError::Io)? {
        let mut entry = entry.map_err(DeployerError::Io)?;
        let entry_path = entry.path().map_err(DeployerError::Io)?.into_owned();
        if !entry_path.starts_with(subtree) || entry.header().entry_type().is_dir() {
            continue;
        }

        let relative = entry_path.strip_prefix(subtree).map_err(|err| {
            DeployerError::Contract(format!(
                "failed to relativize {} under {}: {}",
                entry_path.display(),
                subtree.display(),
                err
            ))
        })?;
        let destination = destination_root.join(relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(DeployerError::Io)?;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).map_err(DeployerError::Io)?;
        fs::write(&destination, bytes).map_err(DeployerError::Io)?;
        copied.push(relative.display().to_string());
    }

    copied.sort();
    Ok(copied)
}

fn copy_pack_subtree_from_zip_gtpack(
    pack_path: &Path,
    subtree: &Path,
    destination_root: &Path,
) -> Result<Vec<String>> {
    let file = fs::File::open(pack_path).map_err(DeployerError::Io)?;
    let mut archive = zip::ZipArchive::new(file).map_err(|err| {
        DeployerError::Contract(format!(
            "failed to open zip pack {}: {err}",
            pack_path.display()
        ))
    })?;
    let mut copied = Vec::new();

    for idx in 0..archive.len() {
        let mut entry = archive.by_index(idx).map_err(|err| {
            DeployerError::Contract(format!(
                "failed to read zip entry {idx} in {}: {err}",
                pack_path.display()
            ))
        })?;
        let Some(entry_name) = entry.enclosed_name().map(|path| path.to_path_buf()) else {
            continue;
        };
        if !entry_name.starts_with(subtree) || entry.is_dir() {
            continue;
        }

        let relative = entry_name.strip_prefix(subtree).map_err(|err| {
            DeployerError::Contract(format!(
                "failed to relativize {} under {}: {}",
                entry_name.display(),
                subtree.display(),
                err
            ))
        })?;
        let destination = destination_root.join(relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(DeployerError::Io)?;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).map_err(DeployerError::Io)?;
        fs::write(&destination, bytes).map_err(DeployerError::Io)?;
        copied.push(relative.display().to_string());
    }

    copied.sort();
    Ok(copied)
}

pub fn resolve_deployer_contract_assets(
    manifest: &PackManifest,
    pack_path: &Path,
) -> Result<Option<ResolvedDeployerContract>> {
    let Some(contract) = get_deployer_contract_v1(manifest)? else {
        return Ok(None);
    };

    let planner = ResolvedPlannerContract {
        flow_id: contract.planner.flow_id.clone(),
        input_schema: load_optional_asset(pack_path, contract.planner.input_schema_ref.as_deref())?,
        output_schema: load_optional_asset(
            pack_path,
            contract.planner.output_schema_ref.as_deref(),
        )?,
        qa_spec: load_optional_asset(pack_path, contract.planner.qa_spec_ref.as_deref())?,
    };

    let mut capabilities = Vec::new();
    for capability in &contract.capabilities {
        capabilities.push(ResolvedCapabilityContract {
            capability: capability.capability,
            flow_id: capability.flow_id.clone(),
            input_schema: load_optional_asset(pack_path, capability.input_schema_ref.as_deref())?,
            output_schema: load_optional_asset(pack_path, capability.output_schema_ref.as_deref())?,
            execution_output_schema: load_optional_asset(
                pack_path,
                capability.execution_output_schema_ref.as_deref(),
            )?,
            qa_spec: load_optional_asset(pack_path, capability.qa_spec_ref.as_deref())?,
            examples: capability
                .example_refs
                .iter()
                .map(|path| load_contract_asset(pack_path, path))
                .collect::<Result<Vec<_>>>()?,
        });
    }

    Ok(Some(ResolvedDeployerContract {
        schema_version: contract.schema_version,
        planner,
        capabilities,
    }))
}

fn load_optional_asset(pack_path: &Path, asset_ref: Option<&str>) -> Result<Option<ContractAsset>> {
    asset_ref
        .map(|asset_ref| load_contract_asset(pack_path, asset_ref))
        .transpose()
}

fn load_contract_asset(pack_path: &Path, asset_ref: &str) -> Result<ContractAsset> {
    let bytes = read_pack_asset(pack_path, asset_ref)?;
    let text = String::from_utf8(bytes.clone()).ok();
    let json = text
        .as_ref()
        .and_then(|text| serde_json::from_str::<JsonValue>(text).ok());
    Ok(ContractAsset {
        path: asset_ref.to_string(),
        json,
        text,
        size_bytes: bytes.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_types::PackId;
    use greentic_types::pack_manifest::{ExtensionInline, ExtensionRef, PackKind, PackManifest};
    use greentic_types::provider::ProviderExtensionInline;
    use semver::Version;
    use std::io::Write;
    use std::str::FromStr;
    use tar::Builder;
    use zip::write::SimpleFileOptions;

    fn sample_manifest() -> PackManifest {
        PackManifest {
            schema_version: "pack-v1".to_string(),
            pack_id: PackId::from_str("dev.greentic.sample").unwrap(),
            name: None,
            version: Version::new(0, 1, 0),
            kind: PackKind::Application,
            publisher: "greentic".to_string(),
            secret_requirements: Vec::new(),
            components: Vec::new(),
            flows: Vec::new(),
            dependencies: Vec::new(),
            capabilities: Vec::new(),
            signatures: Default::default(),
            bootstrap: None,
            extensions: None,
        }
    }

    fn sample_contract() -> DeployerContractV1 {
        DeployerContractV1 {
            schema_version: 1,
            planner: PlannerSpecV1 {
                flow_id: "plan_flow".into(),
                input_schema_ref: Some("assets/schemas/deployer-plan-input.schema.json".into()),
                output_schema_ref: Some("assets/schemas/deployer-plan-output.schema.json".into()),
                qa_spec_ref: Some("assets/qaspecs/plan.json".into()),
            },
            capabilities: vec![
                CapabilitySpecV1 {
                    capability: DeployerCapability::Plan,
                    flow_id: "plan_flow".into(),
                    input_schema_ref: Some("assets/schemas/deployer-plan-input.schema.json".into()),
                    output_schema_ref: Some(
                        "assets/schemas/deployer-plan-output.schema.json".into(),
                    ),
                    execution_output_schema_ref: None,
                    qa_spec_ref: None,
                    example_refs: vec!["assets/examples/plan.json".into()],
                },
                CapabilitySpecV1 {
                    capability: DeployerCapability::Apply,
                    flow_id: "apply_flow".into(),
                    input_schema_ref: None,
                    output_schema_ref: None,
                    execution_output_schema_ref: Some(
                        "assets/schemas/apply-execution-output.schema.json".into(),
                    ),
                    qa_spec_ref: None,
                    example_refs: Vec::new(),
                },
                CapabilitySpecV1 {
                    capability: DeployerCapability::Destroy,
                    flow_id: "destroy_flow".into(),
                    input_schema_ref: None,
                    output_schema_ref: None,
                    execution_output_schema_ref: Some(
                        "assets/schemas/destroy-execution-output.schema.json".into(),
                    ),
                    qa_spec_ref: None,
                    example_refs: Vec::new(),
                },
                CapabilitySpecV1 {
                    capability: DeployerCapability::Status,
                    flow_id: "status_flow".into(),
                    input_schema_ref: None,
                    output_schema_ref: None,
                    execution_output_schema_ref: Some(
                        "assets/schemas/status-execution-output.schema.json".into(),
                    ),
                    qa_spec_ref: None,
                    example_refs: Vec::new(),
                },
            ],
        }
    }

    #[test]
    fn round_trips_contract_through_manifest_extension() {
        let mut manifest = sample_manifest();
        let contract = sample_contract();
        set_deployer_contract_v1(&mut manifest, contract.clone()).unwrap();
        let decoded = get_deployer_contract_v1(&manifest).unwrap().unwrap();
        assert_eq!(decoded, contract);
    }

    #[test]
    fn rejects_duplicate_capabilities() {
        let mut contract = sample_contract();
        contract.capabilities.push(CapabilitySpecV1 {
            capability: DeployerCapability::Plan,
            flow_id: "other_plan".into(),
            input_schema_ref: None,
            output_schema_ref: None,
            execution_output_schema_ref: None,
            qa_spec_ref: None,
            example_refs: Vec::new(),
        });
        let err = contract.validate().unwrap_err();
        assert!(format!("{err}").contains("duplicate capability"));
    }

    #[test]
    fn loads_pack_asset_from_dir_and_gtpack() {
        let base = std::env::current_dir().unwrap().join("target/tmp-tests");
        std::fs::create_dir_all(&base).unwrap();
        let dir = tempfile::tempdir_in(&base).unwrap();
        let relative = "assets/schemas/deployer-plan-input.schema.json";
        let bytes = br#"{"type":"object"}"#;
        let asset_path = dir.path().join(relative);
        std::fs::create_dir_all(asset_path.parent().unwrap()).unwrap();
        std::fs::write(&asset_path, bytes).unwrap();
        assert_eq!(read_pack_asset(dir.path(), relative).unwrap(), bytes);

        let tar_path = dir.path().join("sample.gtpack");
        let mut builder = Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, relative, &bytes[..])
            .expect("append asset");
        let tar_bytes = builder.into_inner().unwrap();
        let mut file = std::fs::File::create(&tar_path).unwrap();
        file.write_all(&tar_bytes).unwrap();

        assert_eq!(read_pack_asset(&tar_path, relative).unwrap(), bytes);
    }

    #[test]
    fn copies_pack_subtree_from_dir_and_gtpack() {
        let base = std::env::current_dir().unwrap().join("target/tmp-tests");
        std::fs::create_dir_all(&base).unwrap();
        let dir = tempfile::tempdir_in(&base).unwrap();

        let source_root = dir.path().join("terraform");
        std::fs::create_dir_all(source_root.join("modules/operator")).unwrap();
        std::fs::write(source_root.join("main.tf"), "module \"root\" {}").unwrap();
        std::fs::write(
            source_root.join("modules/operator/main.tf"),
            "module \"operator\" {}",
        )
        .unwrap();

        let copied =
            copy_pack_subtree(dir.path(), "terraform", &dir.path().join("out-dir")).unwrap();
        assert_eq!(
            copied,
            vec![
                "main.tf".to_string(),
                "modules/operator/main.tf".to_string()
            ]
        );
        assert!(dir.path().join("out-dir/main.tf").exists());
        assert!(dir.path().join("out-dir/modules/operator/main.tf").exists());

        let tar_path = dir.path().join("sample.gtpack");
        let mut builder = Builder::new(Vec::new());
        append_tar_file(&mut builder, "terraform/main.tf", br#"module "root" {}"#);
        append_tar_file(
            &mut builder,
            "terraform/modules/operator/main.tf",
            br#"module "operator" {}"#,
        );
        let tar_bytes = builder.into_inner().unwrap();
        let mut file = std::fs::File::create(&tar_path).unwrap();
        file.write_all(&tar_bytes).unwrap();

        let copied =
            copy_pack_subtree(&tar_path, "terraform", &dir.path().join("out-gtpack")).unwrap();
        assert_eq!(
            copied,
            vec![
                "main.tf".to_string(),
                "modules/operator/main.tf".to_string()
            ]
        );
        assert!(dir.path().join("out-gtpack/main.tf").exists());
        assert!(
            dir.path()
                .join("out-gtpack/modules/operator/main.tf")
                .exists()
        );
    }

    fn append_tar_file(builder: &mut Builder<Vec<u8>>, path: &str, bytes: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, bytes).unwrap();
    }

    #[test]
    fn cloud_target_requirements_apply_operator_image_source_override() {
        assert_eq!(
            operator_image_source_for_provider_override(Provider::Gcp, Some("ghcr")),
            OperatorImageSource::Ghcr
        );
        assert_eq!(
            operator_image_source_for_provider_override(Provider::Gcp, None),
            OperatorImageSource::GcpArtifactRegistry
        );
    }

    #[test]
    fn cloud_target_requirements_for_provider_cover_cloud_targets_only() {
        let aws = CloudTargetRequirementsV1::for_provider(Provider::Aws).expect("aws");
        assert_eq!(aws.target, "aws");
        assert_eq!(aws.target_label, "AWS");
        assert_eq!(aws.provider_pack_filename, "aws.gtpack");
        assert!(aws.remote_bundle_source_required);
        assert!(!aws.credential_requirements.is_empty());
        assert!(aws.variable_requirements.iter().any(|entry| entry.name
            == "GREENTIC_DEPLOY_TERRAFORM_VAR_REMOTE_STATE_BACKEND"
            && entry.required));
        assert!(aws.variable_requirements.iter().any(|entry| entry.name
            == "GREENTIC_DEPLOY_TERRAFORM_VAR_REDIS_URL"
            && !entry.required));

        let azure = CloudTargetRequirementsV1::for_provider(Provider::Azure).expect("azure");
        assert_eq!(azure.target_label, "Azure");
        assert_eq!(azure.provider_pack_filename, "azure.gtpack");
        assert!(azure.variable_requirements.iter().any(|entry| entry.name
            == "GREENTIC_DEPLOY_TERRAFORM_VAR_AZURE_KEY_VAULT_ID"
            && entry.required));

        let gcp = CloudTargetRequirementsV1::for_provider(Provider::Gcp).expect("gcp");
        assert_eq!(gcp.target_label, "GCP");
        assert_eq!(gcp.provider_pack_filename, "gcp.gtpack");
        assert!(gcp.variable_requirements.iter().any(|entry| entry.name
            == "GREENTIC_DEPLOY_TERRAFORM_VAR_GCP_PROJECT_ID"
            && entry.required));
        assert_eq!(
            gcp.variable_requirements
                .iter()
                .find(|entry| entry.name == "GREENTIC_DEPLOY_TERRAFORM_VAR_OPERATOR_IMAGE")
                .and_then(|entry| entry.default_value.as_deref()),
            Some(DEFAULT_GCP_OPERATOR_IMAGE)
        );

        assert!(CloudTargetRequirementsV1::for_provider(Provider::Local).is_none());
        assert!(CloudTargetRequirementsV1::for_provider(Provider::K8s).is_none());
        assert!(CloudTargetRequirementsV1::for_provider(Provider::Generic).is_none());
    }

    #[test]
    fn cloud_deployer_extension_descriptor_for_provider_is_canonical() {
        let aws = CloudDeployerExtensionDescriptorV1::for_provider(Provider::Aws).expect("aws");
        assert_eq!(aws.extension_id, EXT_DEPLOY_AWS);
        assert_eq!(aws.deployer_pack_id, "greentic.deploy.aws");
        assert_eq!(aws.provider_pack_filename, "aws.gtpack");
        assert_eq!(aws.target_id, "aws-ecs-fargate-local");

        let azure =
            CloudDeployerExtensionDescriptorV1::for_provider(Provider::Azure).expect("azure");
        assert_eq!(azure.extension_id, EXT_DEPLOY_AZURE);
        assert_eq!(azure.deployer_pack_id, "greentic.deploy.azure");
        assert_eq!(azure.provider_pack_filename, "azure.gtpack");
        assert_eq!(azure.target_id, "azure-container-apps-local");

        let gcp = CloudDeployerExtensionDescriptorV1::for_provider(Provider::Gcp).expect("gcp");
        assert_eq!(gcp.extension_id, EXT_DEPLOY_GCP);
        assert_eq!(gcp.deployer_pack_id, "greentic.deploy.gcp");
        assert_eq!(gcp.provider_pack_filename, "gcp.gtpack");
        assert_eq!(gcp.target_id, "gcp-cloud-run-local");

        assert!(CloudDeployerExtensionDescriptorV1::for_provider(Provider::Local).is_none());
        assert!(CloudDeployerExtensionDescriptorV1::for_provider(Provider::K8s).is_none());
        assert!(CloudDeployerExtensionDescriptorV1::for_provider(Provider::Generic).is_none());
    }

    #[test]
    fn set_cloud_deployer_extension_ref_writes_manifest_extensions() {
        let mut manifest = sample_manifest();
        set_cloud_deployer_extension_ref(&mut manifest, Provider::Aws).expect("aws ext");
        set_cloud_deployer_extension_ref(&mut manifest, Provider::Gcp).expect("gcp ext");

        let extensions = manifest.extensions.expect("extensions");
        let aws = extensions.get(EXT_DEPLOY_AWS).expect("aws ext entry");
        assert_eq!(aws.kind, EXT_DEPLOY_AWS);
        assert_eq!(aws.version, "0.1.0");
        let aws_inline = aws.inline.as_ref().expect("aws inline");
        let ExtensionInline::Other(aws_value) = aws_inline else {
            panic!("expected Other inline payload for aws");
        };
        let aws_descriptor: CloudDeployerExtensionDescriptorV1 =
            serde_json::from_value(aws_value.clone()).expect("aws descriptor");
        assert_eq!(aws_descriptor.deployer_pack_id, "greentic.deploy.aws");
        assert_eq!(aws_descriptor.provider_pack_filename, "aws.gtpack");

        let gcp = extensions.get(EXT_DEPLOY_GCP).expect("gcp ext entry");
        assert_eq!(gcp.kind, EXT_DEPLOY_GCP);
        assert_eq!(gcp.version, "0.1.0");
        let gcp_inline = gcp.inline.as_ref().expect("gcp inline");
        let ExtensionInline::Other(gcp_value) = gcp_inline else {
            panic!("expected Other inline payload for gcp");
        };
        let gcp_descriptor: CloudDeployerExtensionDescriptorV1 =
            serde_json::from_value(gcp_value.clone()).expect("gcp descriptor");
        assert_eq!(gcp_descriptor.deployer_pack_id, "greentic.deploy.gcp");
        assert_eq!(gcp_descriptor.provider_pack_filename, "gcp.gtpack");
    }

    #[test]
    fn contract_validation_rejects_invalid_shapes_and_finds_capabilities() {
        let mut missing_plan = sample_contract();
        missing_plan
            .capabilities
            .retain(|entry| entry.capability != DeployerCapability::Plan);
        let err = missing_plan.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("must declare the `plan` capability")
        );

        let mut bad_schema = sample_contract();
        bad_schema.schema_version = 2;
        let err = bad_schema.validate().unwrap_err();
        assert!(err.to_string().contains("unsupported"));

        let mut empty_planner = sample_contract();
        empty_planner.planner.flow_id.clear();
        let err = empty_planner.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("planner.flow_id must not be empty")
        );

        let mut empty_capability_flow = sample_contract();
        empty_capability_flow.capabilities[0].flow_id.clear();
        let err = empty_capability_flow.validate().unwrap_err();
        assert!(err.to_string().contains("has empty flow_id"));

        let contract = sample_contract();
        assert_eq!(
            contract
                .capability(DeployerCapability::Apply)
                .map(|entry| entry.flow_id.as_str()),
            Some("apply_flow")
        );
        assert!(contract.capability(DeployerCapability::Rollback).is_none());
    }

    #[test]
    fn get_deployer_contract_rejects_unexpected_inline_type() {
        let mut manifest = sample_manifest();
        let extensions = manifest.extensions.get_or_insert_with(Default::default);
        extensions.insert(
            EXT_DEPLOYER_V1.to_string(),
            ExtensionRef {
                kind: EXT_DEPLOYER_V1.to_string(),
                version: "1.0.0".to_string(),
                digest: None,
                location: None,
                inline: Some(ExtensionInline::Provider(ProviderExtensionInline::default())),
            },
        );
        let err = get_deployer_contract_v1(&manifest).unwrap_err();
        assert!(err.to_string().contains("unexpected type"));
    }

    #[test]
    fn read_pack_asset_and_copy_subtree_reject_parent_refs() {
        let base = std::env::current_dir().unwrap().join("target/tmp-tests");
        std::fs::create_dir_all(&base).unwrap();
        let dir = tempfile::tempdir_in(&base).unwrap();

        let err = read_pack_asset(dir.path(), "../secrets.txt").unwrap_err();
        assert!(
            err.to_string()
                .contains("pack asset ref must stay pack-relative")
        );

        let err =
            copy_pack_subtree(dir.path(), "../terraform", &dir.path().join("out")).unwrap_err();
        assert!(
            err.to_string()
                .contains("pack subtree ref must stay pack-relative")
        );
    }

    #[test]
    fn copy_pack_subtree_from_zip_gtpack() {
        let base = std::env::current_dir().unwrap().join("target/tmp-tests");
        std::fs::create_dir_all(&base).unwrap();
        let dir = tempfile::tempdir_in(&base).unwrap();

        let zip_path = dir.path().join("sample.gtpack");
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        zip.start_file("terraform/main.tf", options).unwrap();
        zip.write_all(br#"module "root" {}"#).unwrap();
        zip.start_file("terraform/modules/operator/main.tf", options)
            .unwrap();
        zip.write_all(br#"module "operator" {}"#).unwrap();
        zip.finish().unwrap();

        let copied =
            copy_pack_subtree(&zip_path, "terraform", &dir.path().join("out-zip")).unwrap();
        assert_eq!(
            copied,
            vec![
                "main.tf".to_string(),
                "modules/operator/main.tf".to_string()
            ]
        );
        assert!(dir.path().join("out-zip/main.tf").exists());
        assert!(dir.path().join("out-zip/modules/operator/main.tf").exists());
    }

    #[test]
    fn resolve_deployer_contract_assets_loads_referenced_files() {
        let base = std::env::current_dir().unwrap().join("target/tmp-tests");
        std::fs::create_dir_all(&base).unwrap();
        let dir = tempfile::tempdir_in(&base).unwrap();

        let planner_input = dir
            .path()
            .join("assets/schemas/deployer-plan-input.schema.json");
        let planner_output = dir
            .path()
            .join("assets/schemas/deployer-plan-output.schema.json");
        let apply_output = dir
            .path()
            .join("assets/schemas/apply-execution-output.schema.json");
        let destroy_output = dir
            .path()
            .join("assets/schemas/destroy-execution-output.schema.json");
        let status_output = dir
            .path()
            .join("assets/schemas/status-execution-output.schema.json");
        let planner_qa = dir.path().join("assets/qaspecs/plan.json");
        let example = dir.path().join("assets/examples/plan.json");
        std::fs::create_dir_all(planner_input.parent().unwrap()).unwrap();
        std::fs::create_dir_all(planner_qa.parent().unwrap()).unwrap();
        std::fs::create_dir_all(example.parent().unwrap()).unwrap();
        std::fs::write(&planner_input, br#"{"type":"object"}"#).unwrap();
        std::fs::write(&planner_output, br#"{"type":"object","title":"plan"}"#).unwrap();
        std::fs::write(&apply_output, br#"{"type":"object","title":"apply"}"#).unwrap();
        std::fs::write(&destroy_output, br#"{"type":"object","title":"destroy"}"#).unwrap();
        std::fs::write(&status_output, br#"{"type":"object","title":"status"}"#).unwrap();
        std::fs::write(&planner_qa, br#"{"questions":[]}"#).unwrap();
        std::fs::write(&example, br#"{"kind":"plan"}"#).unwrap();

        let mut manifest = sample_manifest();
        set_deployer_contract_v1(&mut manifest, sample_contract()).unwrap();
        let resolved = resolve_deployer_contract_assets(&manifest, dir.path())
            .unwrap()
            .expect("resolved");

        assert_eq!(resolved.schema_version, 1);
        assert_eq!(resolved.planner.flow_id, "plan_flow");
        assert_eq!(
            resolved
                .planner
                .input_schema
                .as_ref()
                .and_then(|asset| asset.json.as_ref())
                .and_then(|json| json.get("type"))
                .and_then(|value| value.as_str()),
            Some("object")
        );
        assert_eq!(
            resolved
                .planner
                .qa_spec
                .as_ref()
                .map(|asset| asset.path.as_str()),
            Some("assets/qaspecs/plan.json")
        );
        let plan_capability = resolved
            .capabilities
            .iter()
            .find(|entry| entry.capability == DeployerCapability::Plan)
            .expect("plan capability");
        assert_eq!(plan_capability.flow_id, "plan_flow");
        assert_eq!(plan_capability.examples.len(), 1);
        assert_eq!(
            plan_capability.examples[0].path,
            "assets/examples/plan.json"
        );
        assert_eq!(
            plan_capability.examples[0]
                .json
                .as_ref()
                .and_then(|json| json.get("kind"))
                .and_then(|value| value.as_str()),
            Some("plan")
        );
    }
}
