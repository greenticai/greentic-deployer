variable "kubernetes_namespace" {
  type = string
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

variable "admin_allowed_clients" {
  type = string
}

variable "public_base_url" {
  type = string
}
