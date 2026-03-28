locals {
  module_kind = "operator-azure"
  secret_prefix = trimspace(var.azure_key_vault_uri) != "" ? trimsuffix(var.azure_key_vault_uri, "/") : null
  name_prefix   = "greentic-${substr(md5(var.bundle_digest), 0, 8)}"
  app_port      = 8080
  admin_port    = 8433
  admin_bind    = "127.0.0.1:${local.admin_port}"

  admin_ca_secret_name          = "greentic-admin-ca-${var.environment}"
  admin_server_cert_secret_name = "greentic-admin-server-cert-${var.environment}"
  admin_server_key_secret_name  = "greentic-admin-server-key-${var.environment}"

  can_manage_key_vault_secrets = trimspace(var.azure_key_vault_id) != ""
  resource_group_name          = "${local.name_prefix}-rg"
  log_analytics_name           = "${local.name_prefix}-logs"
  container_env_name           = "${local.name_prefix}-cae"
  container_app_name           = "${local.name_prefix}-app"
  operator_endpoint = trimspace(var.public_base_url) != "" ? var.public_base_url : (
    try(azurerm_container_app.this.latest_revision_fqdn, "") != "" ? "https://${azurerm_container_app.this.latest_revision_fqdn}" : null
  )
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

resource "tls_cert_request" "admin_server" {
  private_key_pem = tls_private_key.admin_server.private_key_pem

  subject {
    common_name  = "localhost"
    organization = "Greentic"
  }

  dns_names    = ["localhost"]
  ip_addresses = ["127.0.0.1"]
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

resource "azurerm_key_vault_secret" "admin_ca" {
  count = local.can_manage_key_vault_secrets ? 1 : 0

  name         = local.admin_ca_secret_name
  value        = tls_self_signed_cert.admin_ca.cert_pem
  key_vault_id = var.azure_key_vault_id
  content_type = "application/x-pem-file"

  tags = {
    ManagedBy = "greentic-demo"
    Bundle    = var.bundle_digest
    Purpose   = "admin-ca"
  }
}

resource "azurerm_key_vault_secret" "admin_server_cert" {
  count = local.can_manage_key_vault_secrets ? 1 : 0

  name         = local.admin_server_cert_secret_name
  value        = tls_locally_signed_cert.admin_server.cert_pem
  key_vault_id = var.azure_key_vault_id
  content_type = "application/x-pem-file"

  tags = {
    ManagedBy = "greentic-demo"
    Bundle    = var.bundle_digest
    Purpose   = "admin-server-cert"
  }
}

resource "azurerm_key_vault_secret" "admin_server_key" {
  count = local.can_manage_key_vault_secrets ? 1 : 0

  name         = local.admin_server_key_secret_name
  value        = tls_private_key.admin_server.private_key_pem
  key_vault_id = var.azure_key_vault_id
  content_type = "application/x-pem-file"

  tags = {
    ManagedBy = "greentic-demo"
    Bundle    = var.bundle_digest
    Purpose   = "admin-server-key"
  }
}

resource "azurerm_resource_group" "this" {
  name     = local.resource_group_name
  location = var.azure_location

  tags = {
    ManagedBy = "greentic-demo"
    Bundle    = var.bundle_digest
  }
}

resource "azurerm_log_analytics_workspace" "this" {
  name                = local.log_analytics_name
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = {
    ManagedBy = "greentic-demo"
    Bundle    = var.bundle_digest
  }
}

resource "azurerm_container_app_environment" "this" {
  name                       = local.container_env_name
  location                   = azurerm_resource_group.this.location
  resource_group_name        = azurerm_resource_group.this.name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id

  tags = {
    ManagedBy = "greentic-demo"
    Bundle    = var.bundle_digest
  }
}

resource "azurerm_container_app" "this" {
  name                         = local.container_app_name
  resource_group_name          = azurerm_resource_group.this.name
  container_app_environment_id = azurerm_container_app_environment.this.id
  revision_mode                = "Single"

  secret {
    name  = "admin-ca-pem"
    value = tls_self_signed_cert.admin_ca.cert_pem
  }

  secret {
    name  = "admin-server-cert-pem"
    value = tls_locally_signed_cert.admin_server.cert_pem
  }

  secret {
    name  = "admin-server-key-pem"
    value = tls_private_key.admin_server.private_key_pem
  }

  ingress {
    external_enabled = true
    target_port      = local.app_port
    transport        = "auto"

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  template {
    min_replicas = 1
    max_replicas = 1

    container {
      name   = "app"
      image  = var.operator_image
      cpu    = 0.5
      memory = "1Gi"
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
        name  = "GREENTIC_ADMIN_CA_SECRET_REF"
        value = local.can_manage_key_vault_secrets ? azurerm_key_vault_secret.admin_ca[0].versionless_id : (local.secret_prefix != null ? "${local.secret_prefix}/secrets/${local.admin_ca_secret_name}" : "")
      }

      env {
        name  = "GREENTIC_ADMIN_SERVER_CERT_SECRET_REF"
        value = local.can_manage_key_vault_secrets ? azurerm_key_vault_secret.admin_server_cert[0].versionless_id : (local.secret_prefix != null ? "${local.secret_prefix}/secrets/${local.admin_server_cert_secret_name}" : "")
      }

      env {
        name  = "GREENTIC_ADMIN_SERVER_KEY_SECRET_REF"
        value = local.can_manage_key_vault_secrets ? azurerm_key_vault_secret.admin_server_key[0].versionless_id : (local.secret_prefix != null ? "${local.secret_prefix}/secrets/${local.admin_server_key_secret_name}" : "")
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

      env {
        name        = "GREENTIC_ADMIN_CA_PEM"
        secret_name = "admin-ca-pem"
      }

      env {
        name        = "GREENTIC_ADMIN_SERVER_CERT_PEM"
        secret_name = "admin-server-cert-pem"
      }

      env {
        name        = "GREENTIC_ADMIN_SERVER_KEY_PEM"
        secret_name = "admin-server-key-pem"
      }
    }
  }

  tags = {
    ManagedBy = "greentic-demo"
    Bundle    = var.bundle_digest
  }
}

# This module now supports real Key Vault secret materialization when
# `azure_key_vault_id` is provided. Compute and runtime resources now target
# Azure Container Apps instead of Azure Container Instances.
