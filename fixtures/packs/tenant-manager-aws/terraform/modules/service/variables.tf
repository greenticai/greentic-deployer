variable "name" { type = string }
variable "aws_region" { type = string }
variable "vpc_id" { type = string }
variable "subnet_ids" { type = list(string) }
variable "image_uri" { type = string }
variable "database_url_secret_arn" { type = string }
variable "master_key_secret_arn" { type = string }
variable "platform_secret_hash_arn" { type = string }
variable "target_group_arn" { type = string }
variable "alb_security_group_id" { type = string }

variable "desired_count" {
  type        = number
  default     = 1
  description = "Initial ECS desired task count. 0 enables scale-to-zero (issuer is down until woken)."
}

variable "min_capacity" {
  type        = number
  default     = 1
  description = "Application Auto Scaling minimum tasks. 0 permits scale-to-zero."
}

variable "max_capacity" {
  type        = number
  default     = 1
  description = "Application Auto Scaling maximum tasks."
}
