terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
    }
    random = {
      source = "hashicorp/random"
    }
  }
}

resource "random_password" "db" {
  length  = 32
  special = false
}

resource "google_secret_manager_secret" "db_password" {
  project   = var.gcp_project
  secret_id = "${var.name}-db-password"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "db_password" {
  secret      = google_secret_manager_secret.db_password.id
  secret_data = random_password.db.result
}

resource "google_sql_database_instance" "this" {
  name             = "${var.name}-db"
  project          = var.gcp_project
  region           = var.gcp_region
  database_version = "POSTGRES_16"

  settings {
    tier = var.db_tier

    backup_configuration {
      enabled                        = true
      start_time                     = "02:00"
      transaction_log_retention_days = 7
    }

    ip_configuration {
      ipv4_enabled = true
    }
  }

  # TODO: set deletion_protection = true for production deployments
  deletion_protection = false
}

resource "google_sql_database" "this" {
  name     = "tenant_manager"
  instance = google_sql_database_instance.this.name
  project  = var.gcp_project
}

resource "google_sql_user" "this" {
  name     = "tmadmin"
  instance = google_sql_database_instance.this.name
  project  = var.gcp_project
  password = random_password.db.result
}
