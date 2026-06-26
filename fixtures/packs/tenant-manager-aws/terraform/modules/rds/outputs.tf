output "database_url_secret_arn" {
  value     = aws_secretsmanager_secret.db_url.arn
  sensitive = true
}

output "db_security_group_id" {
  value = aws_security_group.db.id
}
