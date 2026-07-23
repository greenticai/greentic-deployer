# tenant-manager-aws deployment pack

Deploys the containerized greentic-tenant-manager to AWS: RDS Postgres +
ECS Fargate (the tenant-manager image) + ALB/Route53/ACM HTTPS route.
Consumed via `greentic-deployer aws <cmd> --provider-pack dist/tenant-manager-aws.gtpack`.

## develop environment (external Supabase, scale-to-zero)

One-time secret bootstrap (operator, ap-southeast-1):
```bash
# 1. Master key (STABLE — back it up; changing it makes sealed data unreadable).
MK=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
aws secretsmanager create-secret --name tm-develop-master-key --secret-string "$MK" --region ap-southeast-1

# 2. Platform secret hash (enables /platform tenant bootstrap).
PS=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
aws secretsmanager create-secret --name tm-develop-platform-hash \
  --secret-string "sha256:$(printf %s "$PS" | sha256sum | cut -d' ' -f1)" --region ap-southeast-1

# 3. Supabase URL (MUST include ?sslmode=require).
aws secretsmanager create-secret --name tm-develop-db-url \
  --secret-string 'postgresql://postgres:PASS@db.vzzdzyszbrhkqkmfyuks.supabase.co:5432/postgres?sslmode=require' \
  --region ap-southeast-1
```

> **Shared-ALB listener priority:** `listener_rule_priority` defaults to `100`. The
> shared estate ALB already carries designer-admin/designer rules, so a real apply can
> collide on priority 100. Before applying, list the existing rules
> (`aws elbv2 describe-rules --listener-arn <shared-listener> --region ap-southeast-1`)
> and set an unused `listener_rule_priority` in `examples/develop.answers.json`.

Deploy (credential-gated; run with real AWS creds for the shared estate):
```bash
greentic-deployer aws generate --tenant develop --provider-pack dist/tenant-manager-aws.gtpack --answers examples/develop.answers.json
greentic-deployer aws plan     --tenant develop --provider-pack dist/tenant-manager-aws.gtpack --answers examples/develop.answers.json
greentic-deployer aws apply    --tenant develop --provider-pack dist/tenant-manager-aws.gtpack --answers examples/develop.answers.json
```

Wake / sleep (scale-to-zero control):
```bash
aws ecs update-service --cluster greentic-tm-develop --service greentic-tm-develop --desired-count 1 --region ap-southeast-1   # wake
aws ecs update-service --cluster greentic-tm-develop --service greentic-tm-develop --desired-count 0 --region ap-southeast-1   # sleep
```
