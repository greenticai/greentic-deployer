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

variable "use_default_vpc" {
  type    = bool
  default = true
}

# PR-08: operator secrets keyed by canonical `secrets://...` URI. Materialised
# as one Secrets Manager entry per key under the deployment's admin prefix
# (`greentic/admin/<prefix>/operator/...`); each entry is referenced from the
# task definition's `secrets` block so the container starts with the URI as
# an env var name and the value injected from Secrets Manager.
variable "secrets_map" {
  type      = map(string)
  default   = {}
  sensitive = true
}
