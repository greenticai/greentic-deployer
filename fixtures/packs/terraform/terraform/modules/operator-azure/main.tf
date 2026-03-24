locals {
  module_kind = "operator-azure"
  secret_prefix = trimspace(var.azure_key_vault_uri) != "" ? trimsuffix(var.azure_key_vault_uri, "/") : null
  name_prefix = "greentic-${substr(md5(var.bundle_digest), 0, 8)}"
  app_port    = 8080
  admin_port  = 8433
  admin_bind  = "127.0.0.1:${local.admin_port}"

  admin_ca_secret_name          = "greentic-admin-ca-${var.environment}"
  admin_server_cert_secret_name = "greentic-admin-server-cert-${var.environment}"
  admin_server_key_secret_name  = "greentic-admin-server-key-${var.environment}"

  can_manage_key_vault_secrets = trimspace(var.azure_key_vault_id) != ""
  resource_group_name          = "${local.name_prefix}-rg"
  container_group_name         = "${local.name_prefix}-aci"
  dns_label                    = substr(replace("${local.name_prefix}-${var.environment}", "/[^a-z0-9-]/", ""), 0, 63)
  operator_endpoint = trimspace(var.public_base_url) != "" ? var.public_base_url : (
    azurerm_container_group.this.fqdn != "" ? "http://${azurerm_container_group.this.fqdn}" : null
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

resource "azurerm_container_group" "this" {
  name                = local.container_group_name
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  ip_address_type     = "Public"
  dns_name_label      = local.dns_label
  os_type             = "Linux"
  restart_policy      = "Always"

  tags = {
    ManagedBy = "greentic-demo"
    Bundle    = var.bundle_digest
  }

  container {
    name   = "app"
    image  = var.operator_image
    cpu    = 0.5
    memory = 1.0

    commands = [
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
      port     = local.app_port
      protocol = "TCP"
    }

    environment_variables = merge(
      {
        GREENTIC_BUNDLE_SOURCE                = var.bundle_source
        GREENTIC_BUNDLE_DIGEST                = var.bundle_digest
        GREENTIC_REPO_REGISTRY_BASE           = var.repo_registry_base
        GREENTIC_STORE_REGISTRY_BASE          = var.store_registry_base
        GREENTIC_ADMIN_LISTEN                 = local.admin_bind
        GREENTIC_ADMIN_CA_SECRET_REF          = local.can_manage_key_vault_secrets ? azurerm_key_vault_secret.admin_ca[0].versionless_id : (local.secret_prefix != null ? "${local.secret_prefix}/secrets/${local.admin_ca_secret_name}" : "")
        GREENTIC_ADMIN_SERVER_CERT_SECRET_REF = local.can_manage_key_vault_secrets ? azurerm_key_vault_secret.admin_server_cert[0].versionless_id : (local.secret_prefix != null ? "${local.secret_prefix}/secrets/${local.admin_server_cert_secret_name}" : "")
        GREENTIC_ADMIN_SERVER_KEY_SECRET_REF  = local.can_manage_key_vault_secrets ? azurerm_key_vault_secret.admin_server_key[0].versionless_id : (local.secret_prefix != null ? "${local.secret_prefix}/secrets/${local.admin_server_key_secret_name}" : "")
        GREENTIC_HEALTH_READINESS_PATH        = "/readyz"
        GREENTIC_HEALTH_LIVENESS_PATH         = "/healthz"
        GREENTIC_HEALTH_STARTUP_TIMEOUT_SECONDS = "120"
      },
      trimspace(var.public_base_url) != "" ? {
        PUBLIC_BASE_URL = var.public_base_url
      } : {},
      trimspace(var.admin_allowed_clients) != "" ? {
        GREENTIC_ADMIN_ALLOWED_CLIENTS = var.admin_allowed_clients
      } : {}
    )

    secure_environment_variables = {
      GREENTIC_ADMIN_CA_PEM          = tls_self_signed_cert.admin_ca.cert_pem
      GREENTIC_ADMIN_SERVER_CERT_PEM = tls_locally_signed_cert.admin_server.cert_pem
      GREENTIC_ADMIN_SERVER_KEY_PEM  = tls_private_key.admin_server.private_key_pem
    }
  }
}

# This module now supports real Key Vault secret materialization when
# `azure_key_vault_id` is provided. Compute and runtime resources still remain
# less feature-complete than AWS, but a real Azure deployment path now exists.
