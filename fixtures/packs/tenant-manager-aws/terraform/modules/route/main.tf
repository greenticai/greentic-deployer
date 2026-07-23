terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

resource "aws_security_group" "alb" {
  count  = var.existing_https_listener_arn == "" ? 1 : 0
  name   = "${var.name}-alb"
  vpc_id = var.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lb" "this" {
  count              = var.existing_https_listener_arn == "" ? 1 : 0
  name               = substr("${var.name}-alb", 0, 32)
  load_balancer_type = "application"
  subnets            = var.subnet_ids
  security_groups    = [aws_security_group.alb[0].id]
}

resource "aws_lb_target_group" "this" {
  name        = substr("${var.name}-tg", 0, 32)
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = "/healthz"
    matcher             = "200"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
  }
}

resource "aws_lb_listener" "https" {
  count             = var.existing_https_listener_arn == "" ? 1 : 0
  load_balancer_arn = aws_lb.this[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}

# --- Reuse path: attach to the shared ALB's HTTPS listener -----------------
resource "aws_lb_listener_rule" "host" {
  count        = var.existing_https_listener_arn != "" ? 1 : 0
  listener_arn = var.existing_https_listener_arn
  priority     = var.listener_rule_priority

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
  condition {
    host_header {
      values = [var.domain_name]
    }
  }
}

# Resolve the shared ALB behind the listener, for the Route53 alias target.
# Only needed when we actually create a DNS record for the reuse path, so
# these stay unread (and the plan stays offline-safe) when create_dns_record
# is false.
data "aws_lb_listener" "shared" {
  count = (var.create_dns_record && var.existing_https_listener_arn != "") ? 1 : 0
  arn   = var.existing_https_listener_arn
}

data "aws_lb" "shared" {
  count = (var.create_dns_record && var.existing_https_listener_arn != "") ? 1 : 0
  arn   = data.aws_lb_listener.shared[0].load_balancer_arn
}

data "aws_route53_zone" "this" {
  count        = var.create_dns_record ? 1 : 0
  name         = "${join(".", slice(split(".", var.domain_name), 1, length(split(".", var.domain_name))))}."
  private_zone = false
}

locals {
  # Nested conditionals so the untaken branch (and its data-source index) is
  # never evaluated: with create_dns_record = false, data.aws_lb.shared[0] is
  # not dereferenced even in the reuse path, keeping the plan offline-safe.
  alb_dns_name = var.existing_https_listener_arn != "" ? (var.create_dns_record ? data.aws_lb.shared[0].dns_name : "") : aws_lb.this[0].dns_name
  alb_zone_id  = var.existing_https_listener_arn != "" ? (var.create_dns_record ? data.aws_lb.shared[0].zone_id : "") : aws_lb.this[0].zone_id
}

resource "aws_route53_record" "this" {
  count   = var.create_dns_record ? 1 : 0
  zone_id = data.aws_route53_zone.this[0].zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = local.alb_dns_name
    zone_id                = local.alb_zone_id
    evaluate_target_health = true
  }
}
