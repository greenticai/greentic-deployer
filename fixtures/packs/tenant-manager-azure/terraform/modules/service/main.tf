terraform {
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
    }
  }
}

resource "azurerm_container_app_environment" "this" {
  name                = "${var.name}-env"
  location            = var.location
  resource_group_name = var.resource_group_name
}

resource "azurerm_container_app" "this" {
  name                         = "${var.name}-app"
  container_app_environment_id = azurerm_container_app_environment.this.id
  resource_group_name          = var.resource_group_name
  revision_mode                = "Single"

  identity {
    type = "SystemAssigned"
  }

  secret {
    name                = "db-password"
    key_vault_secret_id = var.db_password_secret_id
    identity            = "System"
  }

  secret {
    name                = "tm-master-key"
    key_vault_secret_id = var.master_key_secret_id
    identity            = "System"
  }

  secret {
    name                = "platform-secret-hash"
    key_vault_secret_id = var.platform_secret_hash_secret_id
    identity            = "System"
  }

  template {
    container {
      name   = "tenant-manager"
      image  = var.image_uri
      cpu    = 0.5
      memory = "1Gi"

      env {
        name  = "TENANT_DATABASE_URL"
        value = "postgres://${var.db_user}@${var.db_fqdn}/${var.db_name}?sslmode=require"
      }

      env {
        name        = "TENANT_DATABASE_PASSWORD"
        secret_name = "db-password"
      }

      env {
        name        = "GREENTIC_TM_MASTER_KEY"
        secret_name = "tm-master-key"
      }

      env {
        name        = "GREENTIC_PLATFORM_SECRET_HASH"
        secret_name = "platform-secret-hash"
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = 8080

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }
}
