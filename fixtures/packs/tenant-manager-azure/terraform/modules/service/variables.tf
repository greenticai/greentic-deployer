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

variable "db_fqdn" {
  type = string
}

variable "db_name" {
  type = string
}

variable "db_user" {
  type = string
}

variable "db_password_secret_id" {
  type        = string
  description = "Azure Key Vault secret ID for the DB password"
}

variable "master_key_secret_id" {
  type        = string
  description = "Azure Key Vault secret ID for GREENTIC_TM_MASTER_KEY"
}

variable "platform_secret_hash_secret_id" {
  type        = string
  description = "Azure Key Vault secret ID for GREENTIC_PLATFORM_SECRET_HASH"
}
