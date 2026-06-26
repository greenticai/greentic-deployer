variable "name" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "location" {
  type = string
}

variable "image_uri" {
  type = string
}

variable "database_url_secret_id" {
  type        = string
  description = "Azure Key Vault secret versionless ID for the full DB connection URL"
}

variable "master_key_secret_id" {
  type        = string
  description = "Azure Key Vault secret ID for GREENTIC_TM_MASTER_KEY"
}

variable "platform_secret_hash_secret_id" {
  type        = string
  description = "Azure Key Vault secret ID for GREENTIC_PLATFORM_SECRET_HASH"
}
