variable "name" { type = string }

variable "gcp_project" { type = string }

variable "gcp_region" { type = string }

variable "domain_name" { type = string }

variable "service_name" { type = string }

variable "create_dns_record" {
  type    = bool
  default = true
}
