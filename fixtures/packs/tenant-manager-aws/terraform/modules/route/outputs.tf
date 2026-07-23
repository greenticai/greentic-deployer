output "target_group_arn" { value = aws_lb_target_group.this.arn }
output "alb_security_group_id" {
  value = var.existing_https_listener_arn != "" ? var.existing_alb_security_group_id : aws_security_group.alb[0].id
}
output "alb_dns_name" { value = local.alb_dns_name }
output "service_url" { value = "https://${var.domain_name}" }
