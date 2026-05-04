resource "null_resource" "dns" {
  triggers = {
    dns_name = var.dns_name
  }
}

