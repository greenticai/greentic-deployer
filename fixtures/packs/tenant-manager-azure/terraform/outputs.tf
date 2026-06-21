output "service_url" {
  value = var.create_dns_record ? module.route.service_url : "https://${module.service.app_fqdn}"
}

output "db_fqdn" {
  value = module.postgres.db_fqdn
}

output "app_fqdn" {
  value = module.service.app_fqdn
}
