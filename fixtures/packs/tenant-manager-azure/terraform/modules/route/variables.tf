variable "domain_name" {
  type = string
}

variable "container_app_id" {
  type        = string
  description = "Resource ID of the Azure Container App to bind the custom domain to"
  default     = ""
}

variable "create_dns_record" {
  type    = bool
  default = true
}
