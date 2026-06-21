variable "name" {
  type = string
}

variable "gcp_project" {
  type = string
}

variable "gcp_region" {
  type = string
}

variable "db_tier" {
  type    = string
  default = "db-f1-micro"
}
