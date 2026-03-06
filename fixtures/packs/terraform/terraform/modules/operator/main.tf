resource "null_resource" "operator" {
  triggers = {
    namespace = var.kubernetes_namespace
    image     = var.operator_image
    bundle    = var.bundle_digest
  }
}

