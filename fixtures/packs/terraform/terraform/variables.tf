variable "kubernetes_namespace" {
  type = string
}

variable "operator_image_digest" {
  type = string
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

variable "admin_allowed_clients" {
  type    = string
  default = ""
}

variable "public_base_url" {
  type    = string
  default = ""
}

variable "remote_state_backend" {
  type = string
}
