locals {
  name = "${var.name_prefix}-${var.environment}"
}

module "cloudsql" {
  source      = "./modules/cloudsql"
  name        = local.name
  gcp_project = var.gcp_project_id
  gcp_region  = var.gcp_region
  db_tier     = var.db_tier
}

module "service" {
  source                         = "./modules/service"
  name                           = local.name
  gcp_project                    = var.gcp_project_id
  gcp_region                     = var.gcp_region
  image_uri                      = var.image_uri
  db_connection_name             = module.cloudsql.connection_name
  db_host                        = module.cloudsql.db_host
  db_name                        = module.cloudsql.db_name
  db_user                        = module.cloudsql.db_user
  db_password_secret_id          = module.cloudsql.db_password_secret_id
  master_key_secret_id           = var.master_key_secret_id
  platform_secret_hash_secret_id = var.platform_secret_hash_secret_id
}

module "route" {
  source            = "./modules/route"
  name              = local.name
  gcp_project       = var.gcp_project_id
  gcp_region        = var.gcp_region
  domain_name       = var.domain_name
  service_name      = module.service.service_name
  create_dns_record = var.create_dns_record
}
