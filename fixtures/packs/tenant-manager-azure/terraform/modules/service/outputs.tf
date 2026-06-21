output "app_fqdn" {
  value = azurerm_container_app.this.ingress[0].fqdn
}

output "app_name" {
  value = azurerm_container_app.this.name
}

output "app_id" {
  value = azurerm_container_app.this.id
}
