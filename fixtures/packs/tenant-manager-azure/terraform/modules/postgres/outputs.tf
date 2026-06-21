output "db_fqdn" {
  value = azurerm_postgresql_flexible_server.this.fqdn
}

output "db_name" {
  value = azurerm_postgresql_flexible_server_database.this.name
}

output "db_user" {
  value = azurerm_postgresql_flexible_server.this.administrator_login
}

output "db_password_secret_id" {
  value = azurerm_key_vault_secret.db_password.id
}
