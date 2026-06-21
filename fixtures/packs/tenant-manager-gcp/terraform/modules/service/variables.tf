variable "name" { type = string }

variable "gcp_project" { type = string }

variable "gcp_region" { type = string }

variable "image_uri" { type = string }

variable "db_connection_name" { type = string }

variable "db_name" { type = string }

variable "db_user" { type = string }

variable "db_password_secret_id" { type = string }

variable "master_key_secret_id" { type = string }

variable "platform_secret_hash_secret_id" { type = string }
