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

variable "operator_image" {
  type = string
}

variable "bundle_digest" {
  type = string
}

variable "bundle_source" {
  type = string
}

variable "repo_registry_base" {
  type = string
}

variable "store_registry_base" {
  type = string
}

variable "admin_allowed_clients" {
  type = string
}

variable "public_base_url" {
  type = string
}

variable "azure_key_vault_uri" {
  type = string
}

variable "azure_key_vault_id" {
  type = string
}

variable "azure_location" {
  type = string
}

variable "admin_access_mode" {
  type    = string
  default = "http-bearer-relay"
}

# PR-08: accepted for parity with the AWS operator module so the top-level
# module call's pass-through compiles. Full Key Vault + Container Apps
# secret wiring lands in a follow-up; until then the value is unused on
# Azure and operator secrets do not reach the deployed runtime there.
variable "secrets_map" {
  type      = map(string)
  default   = {}
  sensitive = true
}
