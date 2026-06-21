variable "azure_subscription_id" {
  type = string
}

variable "azure_resource_group" {
  type = string
}

variable "azure_location" {
  type = string
}

variable "tenant" {
  type    = string
  default = "tenant-manager"
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "name_prefix" {
  type    = string
  default = "greentic-tm"
}

variable "image_uri" {
  type = string
}

variable "db_sku_name" {
  type    = string
  default = "B_Standard_B1ms"
}

variable "domain_name" {
  type = string
}

variable "key_vault_id" {
  type        = string
  description = "Resource ID of an existing Azure Key Vault used to store the generated DB password"
}

variable "master_key_secret_id" {
  type = string
}

variable "platform_secret_hash_secret_id" {
  type = string
}

variable "create_dns_record" {
  type    = bool
  default = true
}
