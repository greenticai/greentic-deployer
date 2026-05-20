variable "cloud" {
  type = string
}

variable "tenant" {
  type = string
}

variable "environment" {
  type = string
}

variable "deployment_name_prefix" {
  type    = string
  default = ""
}

variable "azure_key_vault_uri" {
  type    = string
  default = ""
}

variable "azure_key_vault_id" {
  type    = string
  default = ""
}

variable "azure_location" {
  type    = string
  default = "eastus"
}

variable "gcp_project_id" {
  type    = string
  default = ""
}

variable "gcp_region" {
  type    = string
  default = "us-central1"
}

variable "operator_image_digest" {
  type = string
}

variable "operator_image" {
  type    = string
  default = ""
}

variable "dns_name" {
  type    = string
  default = ""
}

variable "bundle_source" {
  type = string
}

variable "bundle_digest" {
  type = string
}

variable "redis_url" {
  type    = string
  default = ""
}

variable "repo_registry_base" {
  type    = string
  default = ""
}

variable "store_registry_base" {
  type    = string
  default = ""
}

variable "admin_allowed_clients" {
  type    = string
  default = ""
}

variable "public_base_url" {
  type    = string
  default = ""
}

variable "remote_state_backend" {
  type = string
}

variable "aws_use_default_vpc" {
  type    = bool
  default = true
}

# PR-08: operator-provided secrets (keyed by canonical `secrets://...` URI,
# value = UTF-8 string). The AWS operator module materialises each entry as a
# deployment-scoped Secrets Manager secret and injects it into the ECS task
# definition's `secrets` block under the URI as the env-var name, so the
# cloud workload can read it via the same `EnvSecretsManager` path it uses
# locally. Empty default = no operator secrets materialised, terraform behaves
# as before this PR. The bundle artifact never carries these values.
variable "secrets_map" {
  type    = map(string)
  default = {}
}
