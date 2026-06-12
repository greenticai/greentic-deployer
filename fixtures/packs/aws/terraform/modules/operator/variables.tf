variable "cloud" {
  type = string
}

variable "tenant" {
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

variable "bundle_s3_object_ref" {
  type    = string
  default = ""
}

variable "bundle_s3_object_arn" {
  type    = string
  default = ""
}

variable "redis_url" {
  type    = string
  default = ""
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

variable "runtime_secret_prefix" {
  type    = string
  default = ""
}

variable "runtime_secret_env" {
  type    = map(string)
  default = {}
}

variable "secrets_map" {
  type    = map(string)
  default = {}
}

variable "use_default_vpc" {
  type    = bool
  default = true
}
