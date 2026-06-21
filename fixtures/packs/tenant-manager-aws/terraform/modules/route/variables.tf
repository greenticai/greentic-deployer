variable "name" { type = string }
variable "vpc_id" { type = string }
variable "subnet_ids" { type = list(string) }
variable "domain_name" { type = string }
variable "acm_certificate_arn" { type = string }
