output "connection_name" {
  value = google_sql_database_instance.this.connection_name
}

output "db_host" {
  value = google_sql_database_instance.this.public_ip_address
}

output "db_name" {
  value = google_sql_database.this.name
}

output "db_user" {
  value = google_sql_user.this.name
}

output "db_password_secret_id" {
  value = google_secret_manager_secret.db_password.secret_id
}
