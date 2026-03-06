variable "kubernetes_namespace" {
  type = string
}

variable "operator_image_digest" {
  type = string
}

variable "redis_secret_name" {
  type = string
}

variable "dns_name" {
  type = string
}

variable "bundle_source" {
  type = string
}

variable "bundle_digest" {
  type = string
}

variable "otlp_endpoint" {
  type = string
}

variable "remote_state_backend" {
  type = string
}

