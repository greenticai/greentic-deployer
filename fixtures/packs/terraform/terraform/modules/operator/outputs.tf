output "operator_endpoint" {
  value = "http://${aws_lb.this.dns_name}"
}

output "admin_ca_secret_ref" {
  value = aws_secretsmanager_secret.admin_ca.arn
}

output "admin_server_cert_secret_ref" {
  value = aws_secretsmanager_secret.admin_server_cert.arn
}

output "admin_server_key_secret_ref" {
  value = aws_secretsmanager_secret.admin_server_key.arn
}
