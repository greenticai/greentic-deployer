output "operator_endpoint" {
  value = local.operator_endpoint
}

output "admin_access_mode" {
  value = var.admin_access_mode
}

output "admin_public_endpoint" {
  value = local.operator_endpoint != null ? "${local.operator_endpoint}/admin-relay/v1" : null
}

output "admin_ca_secret_ref" {
  value = google_secret_manager_secret.admin_ca.id
}

output "admin_server_cert_secret_ref" {
  value = google_secret_manager_secret.admin_server_cert.id
}

output "admin_server_key_secret_ref" {
  value = google_secret_manager_secret.admin_server_key.id
}

output "admin_client_cert_secret_ref" {
  value = google_secret_manager_secret.admin_client_cert.id
}

output "admin_client_key_secret_ref" {
  value = google_secret_manager_secret.admin_client_key.id
}

output "admin_relay_token_secret_ref" {
  value = google_secret_manager_secret.admin_relay_token.id
}
