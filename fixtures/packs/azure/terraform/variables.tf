variable "cloud" {
  type    = string
  default = "azure"
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
  type    = string
  default = "azurerm"
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
