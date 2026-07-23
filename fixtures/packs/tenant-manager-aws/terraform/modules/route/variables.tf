variable "name" { type = string }
variable "vpc_id" { type = string }
variable "subnet_ids" { type = list(string) }
variable "domain_name" { type = string }
variable "acm_certificate_arn" { type = string }

variable "create_dns_record" {
  type    = bool
  default = true
}

variable "existing_https_listener_arn" {
  type        = string
  default     = ""
  description = "When set, reuse this shared ALB HTTPS listener (add a host-based rule + target group) instead of creating a dedicated ALB."
}

variable "existing_alb_security_group_id" {
  type        = string
  default     = ""
  description = "Security group of the shared ALB, so the ECS service SG can allow ingress from it. Required when existing_https_listener_arn is set."
}

variable "listener_rule_priority" {
  type        = number
  default     = 100
  description = "Priority for the host-based listener rule on the shared ALB."
}
