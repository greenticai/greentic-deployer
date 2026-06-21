terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

resource "google_cloud_run_v2_service" "this" {
  name     = var.name
  location = var.gcp_region
  project  = var.gcp_project

  template {
    annotations = {
      "run.googleapis.com/cloudsql-instances" = var.db_connection_name
    }

    containers {
      image = var.image_uri

      ports {
        container_port = 8080
      }

      env {
        name  = "TENANT_DATABASE_URL"
        value = "postgres://${var.db_user}@/${var.db_name}?host=/cloudsql/${var.db_connection_name}"
      }

      env {
        name = "TENANT_DATABASE_PASSWORD"
        value_source {
          secret_key_ref {
            secret  = var.db_password_secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "GREENTIC_TM_MASTER_KEY"
        value_source {
          secret_key_ref {
            secret  = var.master_key_secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "GREENTIC_PLATFORM_SECRET_HASH"
        value_source {
          secret_key_ref {
            secret  = var.platform_secret_hash_secret_id
            version = "latest"
          }
        }
      }

      startup_probe {
        http_get {
          path = "/healthz"
          port = 8080
        }
        initial_delay_seconds = 5
        period_seconds        = 10
        failure_threshold     = 5
      }

      liveness_probe {
        http_get {
          path = "/healthz"
          port = 8080
        }
        period_seconds    = 30
        failure_threshold = 3
      }
    }
  }
}

resource "google_cloud_run_v2_service_iam_member" "allow_unauthenticated" {
  project  = var.gcp_project
  location = var.gcp_region
  name     = google_cloud_run_v2_service.this.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
