variable "aws_region" { type = string }

variable "tenant" {
  type    = string
  default = "tenant-manager"
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "name_prefix" {
  type    = string
  default = "greentic-tm"
}

variable "image_uri" { type = string }

variable "db_instance_class" {
  type    = string
  default = "db.t4g.micro"
}

variable "domain_name" { type = string }
variable "acm_certificate_arn" { type = string }
variable "vpc_id" { type = string }
variable "subnet_ids" { type = list(string) }
variable "master_key_secret_arn" { type = string }
variable "platform_secret_hash_arn" { type = string }
