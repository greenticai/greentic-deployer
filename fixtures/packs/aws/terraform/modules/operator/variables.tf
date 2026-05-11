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

variable "use_default_vpc" {
  type    = bool
  default = true
}

variable "provision_redis" {
  type    = bool
  default = false
}

variable "redis_node_type" {
  type    = string
  default = "cache.t3.micro"
}

variable "redis_engine_version" {
  type    = string
  default = "7.1"
}
