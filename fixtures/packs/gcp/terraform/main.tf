locals {
  name_prefix         = trimspace(var.deployment_name_prefix) != "" ? var.deployment_name_prefix : "greentic-${substr(md5(var.bundle_digest), 0, 8)}"
  admin_secret_prefix = "greentic/admin/${local.name_prefix}"
  operator_image      = var.operator_image != "" ? var.operator_image : "ghcr.io/greenticai/greentic-start-distroless@${var.operator_image_digest}"
}

module "operator_gcp" {
  source = "./modules/operator"

  cloud                  = var.cloud
  tenant                 = var.tenant
  environment            = var.environment
  deployment_name_prefix = local.name_prefix
  operator_image         = local.operator_image
  bundle_source          = var.bundle_source
  bundle_digest          = var.bundle_digest
  repo_registry_base     = var.repo_registry_base
  store_registry_base    = var.store_registry_base
  admin_allowed_clients  = var.admin_allowed_clients
  public_base_url        = var.public_base_url
  gcp_project_id         = var.gcp_project_id
  gcp_region             = var.gcp_region
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
