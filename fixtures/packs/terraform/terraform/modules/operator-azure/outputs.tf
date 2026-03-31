output "operator_endpoint" {
  value = local.operator_endpoint
}

output "admin_ca_secret_ref" {
  value = local.can_manage_key_vault_secrets ? azurerm_key_vault_secret.admin_ca[0].versionless_id : (
    local.secret_prefix != null ? "${local.secret_prefix}/secrets/${local.admin_ca_secret_name}" : null
  )
}

output "admin_server_cert_secret_ref" {
  value = local.can_manage_key_vault_secrets ? azurerm_key_vault_secret.admin_server_cert[0].versionless_id : (
    local.secret_prefix != null ? "${local.secret_prefix}/secrets/${local.admin_server_cert_secret_name}" : null
  )
}

output "admin_server_key_secret_ref" {
  value = local.can_manage_key_vault_secrets ? azurerm_key_vault_secret.admin_server_key[0].versionless_id : (
    local.secret_prefix != null ? "${local.secret_prefix}/secrets/${local.admin_server_key_secret_name}" : null
  )
}

output "admin_client_cert_secret_ref" {
  value = null
}

output "admin_client_key_secret_ref" {
  value = null
}
