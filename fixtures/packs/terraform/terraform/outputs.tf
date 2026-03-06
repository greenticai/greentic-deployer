output "operator_endpoint" {
  value = "https://${var.dns_name}"
}

output "redis_secret_name" {
  value = var.redis_secret_name
}

