output "service_url" {
  value = var.create_dns_record ? module.route.service_url : "https://${module.service.app_fqdn}"
}

output "database_url_secret_id" {
  value     = module.postgres.database_url_secret_id
  sensitive = true
}

output "app_fqdn" {
  value = module.service.app_fqdn
}
