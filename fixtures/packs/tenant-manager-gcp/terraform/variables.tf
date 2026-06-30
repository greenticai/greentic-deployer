variable "gcp_project_id" { type = string }

variable "gcp_region" { type = string }

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

variable "image_uri" { type = string }

variable "db_tier" {
  type    = string
  default = "db-f1-micro"
}

variable "domain_name" { type = string }

variable "master_key_secret_id" { type = string }

variable "platform_secret_hash_secret_id" { type = string }

variable "create_dns_record" {
  type    = bool
  default = true
}
