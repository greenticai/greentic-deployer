terraform {
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
    }
  }
}

resource "azurerm_container_app_custom_domain" "this" {
  count            = var.create_dns_record ? 1 : 0
  name             = var.domain_name
  container_app_id = var.container_app_id
}
