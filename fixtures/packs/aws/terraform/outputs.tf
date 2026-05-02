output "operator_endpoint" {
  value = module.operator_aws.operator_endpoint
}

output "cloud_provider" {
  value = var.cloud
}

output "admin_ca_secret_ref" {
  value = module.operator_aws.admin_ca_secret_ref
}

output "admin_server_cert_secret_ref" {
  value = module.operator_aws.admin_server_cert_secret_ref
}

output "admin_server_key_secret_ref" {
  value = module.operator_aws.admin_server_key_secret_ref
}

output "admin_client_cert_secret_ref" {
  value = module.operator_aws.admin_client_cert_secret_ref
}

output "admin_client_key_secret_ref" {
  value = module.operator_aws.admin_client_key_secret_ref
}

output "admin_access_mode" {
  value = null
}

output "admin_public_endpoint" {
  value = null
}

output "admin_relay_token_secret_ref" {
  value = null
}
