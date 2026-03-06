resource "null_resource" "redis" {
  triggers = {
    redis_secret_name = var.redis_secret_name
  }
}

