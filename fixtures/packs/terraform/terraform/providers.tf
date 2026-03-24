terraform {
  required_version = ">= 1.8.0"
  backend "s3" {}

  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
    }
    google = {
      source = "hashicorp/google"
    }
  }
}

provider "azurerm" {
  features {}
}

provider "google" {
  project = trimspace(var.gcp_project_id) != "" ? var.gcp_project_id : "greentic-placeholder"
  region  = trimspace(var.gcp_region) != "" ? var.gcp_region : "us-central1"
}
