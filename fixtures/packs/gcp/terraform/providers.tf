terraform {
  required_version = ">= 1.8.0"
  backend "gcs" {}

  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

provider "google" {
  project = trimspace(var.gcp_project_id) != "" ? var.gcp_project_id : "greentic-placeholder"
  region  = trimspace(var.gcp_region) != "" ? var.gcp_region : "us-central1"
}
