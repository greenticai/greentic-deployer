locals {
  module_kind = "operator-gcp"
  name_prefix = trimspace(var.deployment_name_prefix) != "" ? var.deployment_name_prefix : "greentic-${substr(md5(var.bundle_digest), 0, 8)}"
  app_port    = 8080
  admin_port  = 8433
  admin_bind  = "127.0.0.1:${local.admin_port}"

  admin_ca_secret_name          = "greentic-admin-ca-${var.environment}"
  admin_server_cert_secret_name = "greentic-admin-server-cert-${var.environment}"
  admin_server_key_secret_name  = "greentic-admin-server-key-${var.environment}"
  admin_client_cert_secret_name = "greentic-admin-client-cert-${var.environment}"
  admin_client_key_secret_name  = "greentic-admin-client-key-${var.environment}"
  admin_relay_token_secret_name = "greentic-admin-relay-token-${var.environment}"
  admin_relay_token             = sha256(tls_private_key.admin_client.private_key_pem)
  service_name                  = "${local.name_prefix}-run"

  operator_endpoint = trimspace(var.public_base_url) != "" ? var.public_base_url : google_cloud_run_v2_service.this.uri
}

resource "tls_private_key" "admin_ca" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "admin_ca" {
  private_key_pem = tls_private_key.admin_ca.private_key_pem

  subject {
    common_name  = "greentic-admin-ca-${var.environment}"
    organization = "Greentic"
  }

  is_ca_certificate     = true
  validity_period_hours = 24 * 365
  allowed_uses = [
    "cert_signing",
    "crl_signing",
    "digital_signature",
    "key_encipherment",
  ]
}

resource "tls_private_key" "admin_server" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_private_key" "admin_client" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "admin_server" {
  private_key_pem = tls_private_key.admin_server.private_key_pem

  subject {
    common_name  = "localhost"
    organization = "Greentic"
  }

  dns_names    = ["localhost"]
  ip_addresses = ["127.0.0.1"]
}

resource "tls_cert_request" "admin_client" {
  private_key_pem = tls_private_key.admin_client.private_key_pem

  subject {
    common_name  = "local-admin"
    organization = "Greentic"
  }
}

resource "tls_locally_signed_cert" "admin_server" {
  cert_request_pem      = tls_cert_request.admin_server.cert_request_pem
  ca_private_key_pem    = tls_private_key.admin_ca.private_key_pem
  ca_cert_pem           = tls_self_signed_cert.admin_ca.cert_pem
  validity_period_hours = 24 * 365
  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "server_auth",
  ]
}

resource "tls_locally_signed_cert" "admin_client" {
  cert_request_pem      = tls_cert_request.admin_client.cert_request_pem
  ca_private_key_pem    = tls_private_key.admin_ca.private_key_pem
  ca_cert_pem           = tls_self_signed_cert.admin_ca.cert_pem
  validity_period_hours = 24 * 365
  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "client_auth",
  ]
}

resource "google_secret_manager_secret" "admin_ca" {
  project   = var.gcp_project_id
  secret_id = local.admin_ca_secret_name

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "admin_ca" {
  secret      = google_secret_manager_secret.admin_ca.id
  secret_data = tls_self_signed_cert.admin_ca.cert_pem
}

resource "google_secret_manager_secret" "admin_server_cert" {
  project   = var.gcp_project_id
  secret_id = local.admin_server_cert_secret_name

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "admin_server_cert" {
  secret      = google_secret_manager_secret.admin_server_cert.id
  secret_data = tls_locally_signed_cert.admin_server.cert_pem
}

resource "google_secret_manager_secret" "admin_server_key" {
  project   = var.gcp_project_id
  secret_id = local.admin_server_key_secret_name

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "admin_server_key" {
  secret      = google_secret_manager_secret.admin_server_key.id
  secret_data = tls_private_key.admin_server.private_key_pem
}

resource "google_secret_manager_secret" "admin_client_cert" {
  project   = var.gcp_project_id
  secret_id = local.admin_client_cert_secret_name

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "admin_client_cert" {
  secret      = google_secret_manager_secret.admin_client_cert.id
  secret_data = tls_locally_signed_cert.admin_client.cert_pem
}

resource "google_secret_manager_secret" "admin_client_key" {
  project   = var.gcp_project_id
  secret_id = local.admin_client_key_secret_name

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "admin_client_key" {
  secret      = google_secret_manager_secret.admin_client_key.id
  secret_data = tls_private_key.admin_client.private_key_pem
}

resource "google_secret_manager_secret" "admin_relay_token" {
  project   = var.gcp_project_id
  secret_id = local.admin_relay_token_secret_name

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "admin_relay_token" {
  secret      = google_secret_manager_secret.admin_relay_token.id
  secret_data = local.admin_relay_token
}

resource "google_cloud_run_v2_service" "this" {
  name     = local.service_name
  location = var.gcp_region
  project  = var.gcp_project_id
  ingress  = "INGRESS_TRAFFIC_ALL"
  deletion_protection = false

  template {
    scaling {
      min_instance_count = 1
      max_instance_count = 1
    }

    containers {
      image = var.operator_image
      args = [
        "start",
        "--bundle",
        var.bundle_source,
        "--cloudflared",
        "off",
        "--ngrok",
        "off",
        "--admin",
        "--admin-port",
        tostring(local.admin_port)
      ]

      ports {
        container_port = local.app_port
      }

      env {
        name  = "GREENTIC_BUNDLE_SOURCE"
        value = var.bundle_source
      }

      env {
        name  = "GREENTIC_BUNDLE_DIGEST"
        value = var.bundle_digest
      }

      env {
        name  = "GREENTIC_REPO_REGISTRY_BASE"
        value = var.repo_registry_base
      }

      env {
        name  = "GREENTIC_STORE_REGISTRY_BASE"
        value = var.store_registry_base
      }

      env {
        name  = "GREENTIC_ADMIN_LISTEN"
        value = local.admin_bind
      }

      env {
        name  = "GREENTIC_GATEWAY_LISTEN_ADDR"
        value = "0.0.0.0"
      }

      env {
        name  = "GREENTIC_GATEWAY_PORT"
        value = tostring(local.app_port)
      }

      env {
        name  = "GREENTIC_ADMIN_CA_PEM"
        value = tls_self_signed_cert.admin_ca.cert_pem
      }

      env {
        name  = "GREENTIC_ADMIN_SERVER_CERT_PEM"
        value = tls_locally_signed_cert.admin_server.cert_pem
      }

      env {
        name  = "GREENTIC_ADMIN_SERVER_KEY_PEM"
        value = tls_private_key.admin_server.private_key_pem
      }

      env {
        name  = "GREENTIC_ADMIN_CLIENT_CERT_PEM"
        value = tls_locally_signed_cert.admin_client.cert_pem
      }

      env {
        name  = "GREENTIC_ADMIN_CLIENT_KEY_PEM"
        value = tls_private_key.admin_client.private_key_pem
      }

      env {
        name  = "GREENTIC_ADMIN_RELAY_TOKEN"
        value = local.admin_relay_token
      }

      env {
        name  = "GREENTIC_ADMIN_CLIENT_CERT_SECRET_REF"
        value = google_secret_manager_secret.admin_client_cert.id
      }

      env {
        name  = "GREENTIC_ADMIN_CLIENT_KEY_SECRET_REF"
        value = google_secret_manager_secret.admin_client_key.id
      }

      env {
        name  = "GREENTIC_ADMIN_RELAY_TOKEN_SECRET_REF"
        value = google_secret_manager_secret.admin_relay_token.id
      }

      env {
        name  = "GREENTIC_HEALTH_READINESS_PATH"
        value = "/readyz"
      }

      env {
        name  = "GREENTIC_HEALTH_LIVENESS_PATH"
        value = "/healthz"
      }

      env {
        name  = "GREENTIC_HEALTH_STARTUP_TIMEOUT_SECONDS"
        value = "120"
      }

      dynamic "env" {
        for_each = trimspace(var.public_base_url) != "" ? [var.public_base_url] : []
        content {
          name  = "PUBLIC_BASE_URL"
          value = env.value
        }
      }

      dynamic "env" {
        for_each = trimspace(var.admin_allowed_clients) != "" ? [var.admin_allowed_clients] : []
        content {
          name  = "GREENTIC_ADMIN_ALLOWED_CLIENTS"
          value = env.value
        }
      }
    }
  }
}

resource "google_cloud_run_v2_service_iam_member" "public_invoker" {
  project  = var.gcp_project_id
  location = var.gcp_region
  name     = google_cloud_run_v2_service.this.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
