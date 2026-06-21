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
  source            = "./modules/rds"
  name              = local.name
  vpc_id            = var.vpc_id
  subnet_ids        = var.subnet_ids
  db_instance_class = var.db_instance_class
}

module "service" {
  source                   = "./modules/service"
  name                     = local.name
  aws_region               = var.aws_region
  vpc_id                   = var.vpc_id
  subnet_ids               = var.subnet_ids
  image_uri                = var.image_uri
  db_endpoint              = module.rds.db_endpoint
  db_name                  = module.rds.db_name
  db_username              = module.rds.db_username
  db_password_secret_arn   = module.rds.db_password_secret_arn
  master_key_secret_arn    = var.master_key_secret_arn
  platform_secret_hash_arn = var.platform_secret_hash_arn
  target_group_arn         = module.route.target_group_arn
  alb_security_group_id    = module.route.alb_security_group_id
}

# DB ingress from the service SG, declared at the root so neither module depends
# on the other's security group (avoids a module dependency cycle).
resource "aws_security_group_rule" "db_from_service" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = module.rds.db_security_group_id
  source_security_group_id = module.service.service_security_group_id
}
