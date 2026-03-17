module "operator" {
  source = "./modules/operator"

  kubernetes_namespace = var.kubernetes_namespace
  operator_image       = "ghcr.io/greenticai/greentic-runtime@${var.operator_image_digest}"
  bundle_source       = var.bundle_source
  bundle_digest       = var.bundle_digest
  otlp_endpoint       = var.otlp_endpoint
}

module "dns" {
  source = "./modules/dns"

  dns_name = var.dns_name
}

module "registry" {
  source = "./modules/registry"

  bundle_source = var.bundle_source
  bundle_digest = var.bundle_digest
}

module "redis" {
  source = "./modules/redis"

  redis_secret_name = var.redis_secret_name
}
