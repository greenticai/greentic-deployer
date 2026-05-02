output "operator_endpoint" {
  value = module.operator_gcp.operator_endpoint
}

output "cloud_provider" {
  value = var.cloud
}

output "admin_ca_secret_ref" {
  value = module.operator_gcp.admin_ca_secret_ref
}

output "admin_server_cert_secret_ref" {
  value = module.operator_gcp.admin_server_cert_secret_ref
}

output "admin_server_key_secret_ref" {
  value = module.operator_gcp.admin_server_key_secret_ref
}

output "admin_client_cert_secret_ref" {
  value = module.operator_gcp.admin_client_cert_secret_ref
}

output "admin_client_key_secret_ref" {
  value = module.operator_gcp.admin_client_key_secret_ref
}

output "admin_access_mode" {
  value = module.operator_gcp.admin_access_mode
}

output "admin_public_endpoint" {
  value = module.operator_gcp.admin_public_endpoint
}

output "admin_relay_token_secret_ref" {
  value = module.operator_gcp.admin_relay_token_secret_ref
}
