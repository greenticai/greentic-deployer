output "operator_endpoint" {
  value = "http://${aws_lb.this.dns_name}"
}
