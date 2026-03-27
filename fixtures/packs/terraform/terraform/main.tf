locals {
  name_prefix         = "greentic-${substr(md5(var.bundle_digest), 0, 8)}"
  admin_secret_prefix = "greentic/admin/${local.name_prefix}"
}

module "operator_aws" {
  count  = var.cloud == "aws" ? 1 : 0
  source = "./modules/operator"

  cloud               = var.cloud
  operator_image      = "ghcr.io/greenticai/greentic-start-distroless@${var.operator_image_digest}"
  bundle_source       = var.bundle_source
  bundle_digest       = var.bundle_digest
  repo_registry_base  = var.repo_registry_base
  store_registry_base = var.store_registry_base
  admin_allowed_clients = var.admin_allowed_clients
  public_base_url     = var.public_base_url
  use_default_vpc     = var.aws_use_default_vpc
}

module "operator_azure" {
  count  = var.cloud == "azure" ? 1 : 0
  source = "./modules/operator-azure"

  cloud               = var.cloud
  environment         = var.environment
  bundle_digest       = var.bundle_digest
  bundle_source       = var.bundle_source
  repo_registry_base  = var.repo_registry_base
  store_registry_base = var.store_registry_base
  operator_image      = "ghcr.io/greenticai/greentic-start-distroless@${var.operator_image_digest}"
  admin_allowed_clients = var.admin_allowed_clients
  public_base_url     = var.public_base_url
  azure_key_vault_uri = var.azure_key_vault_uri
  azure_key_vault_id  = var.azure_key_vault_id
  azure_location      = var.azure_location
}

module "operator_gcp" {
  count  = var.cloud == "gcp" ? 1 : 0
  source = "./modules/operator-gcp"

  cloud               = var.cloud
  environment         = var.environment
  bundle_digest       = var.bundle_digest
  bundle_source       = var.bundle_source
  repo_registry_base  = var.repo_registry_base
  store_registry_base = var.store_registry_base
  operator_image      = "ghcr.io/greenticai/greentic-start-distroless@${var.operator_image_digest}"
  admin_allowed_clients = var.admin_allowed_clients
  public_base_url     = var.public_base_url
  gcp_project_id      = var.gcp_project_id
  gcp_region          = var.gcp_region
}

module "dns" {
  count  = var.dns_name != "" ? 1 : 0
  source = "./modules/dns"

  dns_name = var.dns_name
}

module "registry" {
  source = "./modules/registry"

  bundle_source = var.bundle_source
  bundle_digest = var.bundle_digest
}
