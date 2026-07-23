output "service_url" { value = module.route.service_url }
output "database_url_secret_arn" {
  value     = local.effective_database_url_secret_arn
  sensitive = true
}
output "alb_dns_name" { value = module.route.alb_dns_name }
