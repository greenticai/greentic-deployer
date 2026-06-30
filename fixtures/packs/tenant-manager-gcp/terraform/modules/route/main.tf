terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

resource "google_cloud_run_domain_mapping" "this" {
  count    = var.create_dns_record ? 1 : 0
  name     = var.domain_name
  location = var.gcp_region
  project  = var.gcp_project

  metadata {
    namespace = var.gcp_project
  }

  spec {
    route_name = var.service_name
  }
}
