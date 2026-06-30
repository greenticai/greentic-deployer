variable "name" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "location" {
  type = string
}

variable "db_sku_name" {
  type    = string
  default = "B_Standard_B1ms"
}

variable "db_admin_login" {
  type    = string
  default = "tmadmin"
}

variable "key_vault_id" {
  type        = string
  description = "Resource ID of the Azure Key Vault to store the generated DB password secret"
}
