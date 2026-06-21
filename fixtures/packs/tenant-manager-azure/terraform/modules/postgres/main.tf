terraform {
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
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

resource "azurerm_postgresql_flexible_server" "this" {
  name                   = "${var.name}-postgres"
  resource_group_name    = var.resource_group_name
  location               = var.location
  version                = "16"
  administrator_login    = var.db_admin_login
  administrator_password = random_password.db.result
  sku_name               = var.db_sku_name
  storage_mb             = 32768

  backup_retention_days        = 7
  geo_redundant_backup_enabled = false
}

resource "azurerm_postgresql_flexible_server_database" "this" {
  name      = "tenant_manager"
  server_id = azurerm_postgresql_flexible_server.this.id
  collation = "en_US.utf8"
  charset   = "utf8"
}

resource "azurerm_key_vault_secret" "db_url" {
  name         = "${var.name}-db-url"
  value        = "postgres://${azurerm_postgresql_flexible_server.this.administrator_login}:${random_password.db.result}@${azurerm_postgresql_flexible_server.this.fqdn}:5432/${azurerm_postgresql_flexible_server_database.this.name}?sslmode=require"
  key_vault_id = var.key_vault_id
}
