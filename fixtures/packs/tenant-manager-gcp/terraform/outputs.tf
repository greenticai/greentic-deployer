output "service_url" {
  value = var.create_dns_record ? module.route.service_url : module.service.service_uri
}
output "db_connection_name" { value = module.cloudsql.connection_name }
output "cloud_run_uri" { value = module.service.service_uri }
