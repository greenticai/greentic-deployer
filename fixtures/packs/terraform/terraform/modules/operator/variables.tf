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

variable "otlp_endpoint" {
  type = string
}
