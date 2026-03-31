output "operator_endpoint" {
  value = var.cloud == "aws" ? module.operator_aws[0].operator_endpoint : (
    var.cloud == "azure" ? module.operator_azure[0].operator_endpoint : module.operator_gcp[0].operator_endpoint
  )
}

output "cloud_provider" {
  value = var.cloud
}

output "admin_ca_secret_ref" {
  value = var.cloud == "aws" ? module.operator_aws[0].admin_ca_secret_ref : (
    var.cloud == "azure" ? module.operator_azure[0].admin_ca_secret_ref : module.operator_gcp[0].admin_ca_secret_ref
  )
}

output "admin_server_cert_secret_ref" {
  value = var.cloud == "aws" ? module.operator_aws[0].admin_server_cert_secret_ref : (
    var.cloud == "azure" ? module.operator_azure[0].admin_server_cert_secret_ref : module.operator_gcp[0].admin_server_cert_secret_ref
  )
}

output "admin_server_key_secret_ref" {
  value = var.cloud == "aws" ? module.operator_aws[0].admin_server_key_secret_ref : (
    var.cloud == "azure" ? module.operator_azure[0].admin_server_key_secret_ref : module.operator_gcp[0].admin_server_key_secret_ref
  )
}

output "admin_client_cert_secret_ref" {
  value = var.cloud == "aws" ? module.operator_aws[0].admin_client_cert_secret_ref : (
    var.cloud == "azure" ? module.operator_azure[0].admin_client_cert_secret_ref : module.operator_gcp[0].admin_client_cert_secret_ref
  )
}

output "admin_client_key_secret_ref" {
  value = var.cloud == "aws" ? module.operator_aws[0].admin_client_key_secret_ref : (
    var.cloud == "azure" ? module.operator_azure[0].admin_client_key_secret_ref : module.operator_gcp[0].admin_client_key_secret_ref
  )
}
