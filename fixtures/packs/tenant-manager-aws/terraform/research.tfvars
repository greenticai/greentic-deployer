offline_plan             = true
create_dns_record        = false
aws_region               = "ap-southeast-1"
environment              = "research"
name_prefix              = "greentic-tm"
image_uri                = "123456789012.dkr.ecr.ap-southeast-1.amazonaws.com/greentic-tenant-manager@sha256:0000000000000000000000000000000000000000000000000000000000000000"
domain_name              = "id.research.greentic.cloud"
acm_certificate_arn      = "arn:aws:acm:ap-southeast-1:123456789012:certificate/00000000-0000-0000-0000-000000000000"
vpc_id                   = "vpc-00000000000000000"
subnet_ids               = ["subnet-00000000000000000", "subnet-11111111111111111"]
master_key_secret_arn    = "arn:aws:secretsmanager:ap-southeast-1:123456789012:secret:tm-research-master-key"
platform_secret_hash_arn = "arn:aws:secretsmanager:ap-southeast-1:123456789012:secret:tm-research-platform-hash"
database_url_secret_arn  = "arn:aws:secretsmanager:ap-southeast-1:123456789012:secret:tm-research-db-url"

# ALWAYS-ON (NOT scale-to-zero) — research is live auth for designer-admin.
desired_count = 1
min_capacity  = 1
max_capacity  = 2

existing_https_listener_arn    = "arn:aws:elasticloadbalancing:ap-southeast-1:123456789012:listener/app/shared-alb/abc/def"
existing_alb_security_group_id = "sg-00000000000000000"
listener_rule_priority         = 90
