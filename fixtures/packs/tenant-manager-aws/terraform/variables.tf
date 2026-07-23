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

variable "offline_plan" {
  type    = bool
  default = false
}

variable "create_dns_record" {
  type    = bool
  default = true
}

variable "database_url_secret_arn" {
  type        = string
  default     = ""
  description = "ARN of a Secrets Manager secret holding the full libpq TENANT_DATABASE_URL (incl. ?sslmode=require). When set, an external Postgres (e.g. Supabase) is used and the RDS module is NOT created."
}
