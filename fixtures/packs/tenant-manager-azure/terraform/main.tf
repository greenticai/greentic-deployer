locals {
  name = "${var.name_prefix}-${var.environment}"
}

module "postgres" {
  source              = "./modules/postgres"
  name                = local.name
  resource_group_name = var.azure_resource_group
  location            = var.azure_location
  db_sku_name         = var.db_sku_name
  key_vault_id        = var.key_vault_id
}

module "service" {
  source                         = "./modules/service"
  name                           = local.name
  resource_group_name            = var.azure_resource_group
  location                       = var.azure_location
  image_uri                      = var.image_uri
  db_fqdn                        = module.postgres.db_fqdn
  db_name                        = module.postgres.db_name
  db_user                        = module.postgres.db_user
  db_password_secret_id          = module.postgres.db_password_secret_id
  master_key_secret_id           = var.master_key_secret_id
  platform_secret_hash_secret_id = var.platform_secret_hash_secret_id
}

module "route" {
  source              = "./modules/route"
  name                = local.name
  resource_group_name = var.azure_resource_group
  domain_name         = var.domain_name
  container_app_id    = module.service.app_id
  create_dns_record   = var.create_dns_record
}
