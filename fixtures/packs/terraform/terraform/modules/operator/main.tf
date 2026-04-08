data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_vpc" "default" {
  count   = var.use_default_vpc ? 1 : 0
  default = true
}

data "aws_subnets" "default" {
  count = var.use_default_vpc ? 1 : 0

  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default[0].id]
  }

  filter {
    name   = "default-for-az"
    values = ["true"]
  }
}

locals {
  name_prefix = "greentic-${substr(md5(var.bundle_digest), 0, 8)}"
  app_port    = 8080
  admin_port  = 8433
  admin_bind  = "127.0.0.1:${local.admin_port}"
  effective_public_base_url = trimspace(var.public_base_url) != "" ? var.public_base_url : "http://${aws_lb.this.dns_name}"
  admin_secret_prefix = "greentic/admin/${local.name_prefix}"
  effective_vpc_id = var.use_default_vpc ? data.aws_vpc.default[0].id : aws_vpc.this[0].id
  effective_subnet_ids = var.use_default_vpc ? slice(data.aws_subnets.default[0].ids, 0, min(2, length(data.aws_subnets.default[0].ids))) : aws_subnet.public[*].id
  common_tags = {
    ManagedBy = "greentic-demo"
    Bundle    = var.bundle_digest
  }
}

resource "tls_private_key" "admin_ca" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "admin_ca" {
  private_key_pem = tls_private_key.admin_ca.private_key_pem

  subject {
    common_name  = "${local.name_prefix}-admin-ca"
    organization = "Greentic"
  }

  is_ca_certificate     = true
  validity_period_hours = 24 * 365
  allowed_uses = [
    "cert_signing",
    "crl_signing",
    "digital_signature",
    "key_encipherment",
  ]
}

resource "tls_private_key" "admin_server" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_private_key" "admin_client" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "admin_server" {
  private_key_pem = tls_private_key.admin_server.private_key_pem

  subject {
    common_name  = "localhost"
    organization = "Greentic"
  }

  dns_names    = ["localhost"]
  ip_addresses = ["127.0.0.1"]
}

resource "tls_cert_request" "admin_client" {
  private_key_pem = tls_private_key.admin_client.private_key_pem

  subject {
    common_name  = "local-admin"
    organization = "Greentic"
  }
}

resource "tls_locally_signed_cert" "admin_server" {
  cert_request_pem      = tls_cert_request.admin_server.cert_request_pem
  ca_private_key_pem    = tls_private_key.admin_ca.private_key_pem
  ca_cert_pem           = tls_self_signed_cert.admin_ca.cert_pem
  validity_period_hours = 24 * 365
  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "server_auth",
  ]
}

resource "tls_locally_signed_cert" "admin_client" {
  cert_request_pem      = tls_cert_request.admin_client.cert_request_pem
  ca_private_key_pem    = tls_private_key.admin_ca.private_key_pem
  ca_cert_pem           = tls_self_signed_cert.admin_ca.cert_pem
  validity_period_hours = 24 * 365
  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "client_auth",
  ]
}

resource "aws_vpc" "this" {
  count = var.use_default_vpc ? 0 : 1

  cidr_block           = "10.42.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-vpc"
  })
}

resource "aws_internet_gateway" "this" {
  count = var.use_default_vpc ? 0 : 1

  vpc_id = aws_vpc.this[0].id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-igw"
  })
}

resource "aws_subnet" "public" {
  count = var.use_default_vpc ? 0 : 2

  vpc_id                  = aws_vpc.this[0].id
  cidr_block              = cidrsubnet(aws_vpc.this[0].cidr_block, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-public-${count.index + 1}"
  })
}

resource "aws_route_table" "public" {
  count = var.use_default_vpc ? 0 : 1

  vpc_id = aws_vpc.this[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this[0].id
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-public"
  })
}

resource "aws_route_table_association" "public" {
  count = var.use_default_vpc ? 0 : 2

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_security_group" "alb" {
  name        = "${local.name_prefix}-alb"
  description = "ALB ingress for Greentic demo"
  vpc_id      = local.effective_vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

resource "aws_security_group" "service" {
  name        = "${local.name_prefix}-svc"
  description = "ECS service ingress from ALB"
  vpc_id      = local.effective_vpc_id

  ingress {
    from_port       = local.app_port
    to_port         = local.app_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

resource "aws_lb" "this" {
  name               = "${local.name_prefix}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = local.effective_subnet_ids

  tags = local.common_tags
}

resource "aws_lb_target_group" "this" {
  name_prefix = "gtg-"
  port        = local.app_port
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = local.effective_vpc_id

  lifecycle {
    create_before_destroy = true
  }

  health_check {
    enabled             = true
    path                = "/readyz"
    matcher             = "200-399"
    healthy_threshold   = 2
    unhealthy_threshold = 5
    interval            = 30
    timeout             = 5
  }

  tags = local.common_tags
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}

resource "aws_ecs_cluster" "this" {
  name = "${local.name_prefix}-cluster"

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/greentic/demo/${local.name_prefix}"
  retention_in_days = 7

  tags = local.common_tags
}

resource "aws_iam_role" "task_execution" {
  name = "${local.name_prefix}-task-exec"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "task_execution" {
  role       = aws_iam_role.task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_secretsmanager_secret" "admin_ca" {
  name_prefix = "${local.admin_secret_prefix}/ca-"

  recovery_window_in_days = 0

  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "admin_ca" {
  secret_id     = aws_secretsmanager_secret.admin_ca.id
  secret_string = tls_self_signed_cert.admin_ca.cert_pem
}

resource "aws_secretsmanager_secret" "admin_server_cert" {
  name_prefix = "${local.admin_secret_prefix}/server-cert-"

  recovery_window_in_days = 0

  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "admin_server_cert" {
  secret_id     = aws_secretsmanager_secret.admin_server_cert.id
  secret_string = tls_locally_signed_cert.admin_server.cert_pem
}

resource "aws_secretsmanager_secret" "admin_server_key" {
  name_prefix = "${local.admin_secret_prefix}/server-key-"

  recovery_window_in_days = 0

  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "admin_server_key" {
  secret_id     = aws_secretsmanager_secret.admin_server_key.id
  secret_string = tls_private_key.admin_server.private_key_pem
}

resource "aws_secretsmanager_secret" "admin_client_cert" {
  name_prefix = "${local.admin_secret_prefix}/client-cert-"

  recovery_window_in_days = 0

  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "admin_client_cert" {
  secret_id     = aws_secretsmanager_secret.admin_client_cert.id
  secret_string = tls_locally_signed_cert.admin_client.cert_pem
}

resource "aws_secretsmanager_secret" "admin_client_key" {
  name_prefix = "${local.admin_secret_prefix}/client-key-"

  recovery_window_in_days = 0

  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "admin_client_key" {
  secret_id     = aws_secretsmanager_secret.admin_client_key.id
  secret_string = tls_private_key.admin_client.private_key_pem
}

resource "aws_iam_role_policy" "task_execution_admin_secrets" {
  name = "${local.name_prefix}-task-exec-admin-secrets"
  role = aws_iam_role.task_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          aws_secretsmanager_secret.admin_ca.arn,
          aws_secretsmanager_secret.admin_server_cert.arn,
          aws_secretsmanager_secret.admin_server_key.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "task_execution_ecs_exec" {
  name = "${local.name_prefix}-task-exec-ecs-exec"
  role = aws_iam_role.task_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_ecs_task_definition" "this" {
  family                   = "${local.name_prefix}-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.task_execution.arn
  task_role_arn            = aws_iam_role.task_execution.arn

  container_definitions = jsonencode([
    {
      name      = "app"
      image     = var.operator_image
      essential = true
      command = [
        "start",
        "--bundle",
        var.bundle_source,
        "--cloudflared",
        "off",
        "--ngrok",
        "off",
        "--admin",
        "--admin-port",
        tostring(local.admin_port)
      ]
      portMappings = [
        {
          containerPort = local.app_port
          hostPort      = local.app_port
          protocol      = "tcp"
        }
      ]
      environment = concat(
        [
          {
            name  = "GREENTIC_BUNDLE_SOURCE"
            value = var.bundle_source
          },
          {
            name  = "GREENTIC_BUNDLE_DIGEST"
            value = var.bundle_digest
          },
          {
            name  = "GREENTIC_REPO_REGISTRY_BASE"
            value = var.repo_registry_base
          },
          {
            name  = "GREENTIC_STORE_REGISTRY_BASE"
            value = var.store_registry_base
          },
          {
            name  = "GREENTIC_ADMIN_LISTEN"
            value = local.admin_bind
          },
          {
            name  = "GREENTIC_GATEWAY_LISTEN_ADDR"
            value = "0.0.0.0"
          },
          {
            name  = "GREENTIC_GATEWAY_PORT"
            value = tostring(local.app_port)
          },
          {
            name  = "GREENTIC_ADMIN_CA_SECRET_REF"
            value = aws_secretsmanager_secret.admin_ca.arn
          },
          {
            name  = "GREENTIC_ADMIN_SERVER_CERT_SECRET_REF"
            value = aws_secretsmanager_secret.admin_server_cert.arn
          },
          {
            name  = "GREENTIC_ADMIN_SERVER_KEY_SECRET_REF"
            value = aws_secretsmanager_secret.admin_server_key.arn
          },
          {
            name  = "GREENTIC_HEALTH_READINESS_PATH"
            value = "/readyz"
          },
          {
            name  = "GREENTIC_HEALTH_LIVENESS_PATH"
            value = "/healthz"
          },
          {
            name  = "GREENTIC_HEALTH_STARTUP_TIMEOUT_SECONDS"
            value = "120"
          }
        ],
        [
          {
            name  = "PUBLIC_BASE_URL"
            value = local.effective_public_base_url
          }
        ],
        var.admin_allowed_clients != "" ? [
          {
            name  = "GREENTIC_ADMIN_ALLOWED_CLIENTS"
            value = var.admin_allowed_clients
          }
        ] : []
      )
      secrets = [
        {
          name      = "GREENTIC_ADMIN_CA_PEM"
          valueFrom = aws_secretsmanager_secret.admin_ca.arn
        },
        {
          name      = "GREENTIC_ADMIN_SERVER_CERT_PEM"
          valueFrom = aws_secretsmanager_secret.admin_server_cert.arn
        },
        {
          name      = "GREENTIC_ADMIN_SERVER_KEY_PEM"
          valueFrom = aws_secretsmanager_secret.admin_server_key.arn
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.this.name
          awslogs-region        = data.aws_region.current.name
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])

  tags = local.common_tags
}

data "aws_region" "current" {}

resource "aws_ecs_service" "this" {
  name            = "${local.name_prefix}-service"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  enable_execute_command = true

  network_configuration {
    subnets          = local.effective_subnet_ids
    security_groups  = [aws_security_group.service.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this.arn
    container_name   = "app"
    container_port   = local.app_port
  }

  depends_on = [aws_lb_listener.http]

  tags = local.common_tags
}
