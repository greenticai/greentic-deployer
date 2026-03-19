module "operator" {
  source = "./modules/operator"

  kubernetes_namespace = var.kubernetes_namespace
  operator_image = "ghcr.io/greenticai/gtc-distroless@${var.operator_image_digest}"
  bundle_source  = var.bundle_source
  bundle_digest  = var.bundle_digest
  admin_allowed_clients = var.admin_allowed_clients
  public_base_url = var.public_base_url
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
