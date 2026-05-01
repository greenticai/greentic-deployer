resource "null_resource" "registry" {
  triggers = {
    bundle_source = var.bundle_source
    bundle_digest = var.bundle_digest
  }
}

