# tenant-manager-aws deployment pack

Deploys the containerized greentic-tenant-manager to AWS: RDS Postgres +
ECS Fargate (the tenant-manager image) + ALB/Route53/ACM HTTPS route.
Consumed via `greentic-deployer aws <cmd> --provider-pack dist/tenant-manager-aws.gtpack`.
