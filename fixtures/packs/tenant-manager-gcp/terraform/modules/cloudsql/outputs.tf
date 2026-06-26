output "connection_name" {
  value = google_sql_database_instance.this.connection_name
}

output "database_url_secret_id" {
  value     = google_secret_manager_secret.db_url.secret_id
  sensitive = true
}
