output "operator_endpoint" {
  value = local.effective_public_base_url
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

output "admin_client_cert_secret_ref" {
  value = aws_secretsmanager_secret.admin_client_cert.arn
}

output "admin_client_key_secret_ref" {
  value = aws_secretsmanager_secret.admin_client_key.arn
}
