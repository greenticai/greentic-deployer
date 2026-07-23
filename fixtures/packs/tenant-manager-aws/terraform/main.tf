locals {
  name = "${var.name_prefix}-${var.environment}"
}

module "route" {
  source              = "./modules/route"
  name                = local.name
  vpc_id              = var.vpc_id
  subnet_ids          = var.subnet_ids
  domain_name         = var.domain_name
  acm_certificate_arn = var.acm_certificate_arn
  create_dns_record   = var.create_dns_record
}

module "rds" {
  count             = var.database_url_secret_arn == "" ? 1 : 0
  source            = "./modules/rds"
  name              = local.name
  vpc_id            = var.vpc_id
  subnet_ids        = var.subnet_ids
  db_instance_class = var.db_instance_class
}

locals {
  # External secret when provided; otherwise the RDS-provisioned secret.
  effective_database_url_secret_arn = var.database_url_secret_arn != "" ? var.database_url_secret_arn : module.rds[0].database_url_secret_arn
}

module "service" {
  source                   = "./modules/service"
  name                     = local.name
  aws_region               = var.aws_region
  vpc_id                   = var.vpc_id
  subnet_ids               = var.subnet_ids
  image_uri                = var.image_uri
  database_url_secret_arn  = local.effective_database_url_secret_arn
  master_key_secret_arn    = var.master_key_secret_arn
  platform_secret_hash_arn = var.platform_secret_hash_arn
  target_group_arn         = module.route.target_group_arn
  alb_security_group_id    = module.route.alb_security_group_id
  desired_count            = var.desired_count
  min_capacity             = var.min_capacity
  max_capacity             = var.max_capacity
}

# Only needed when RDS is provisioned (both SGs then exist).
resource "aws_security_group_rule" "db_from_service" {
  count                    = var.database_url_secret_arn == "" ? 1 : 0
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = module.rds[0].db_security_group_id
  source_security_group_id = module.service.service_security_group_id
}
