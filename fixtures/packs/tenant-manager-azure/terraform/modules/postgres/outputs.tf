output "database_url_secret_id" {
  value     = azurerm_key_vault_secret.db_url.versionless_id
  sensitive = true
}
