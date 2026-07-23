# Research cutover runbook — Cloudflare Worker + D1 → ECS + Supabase

Moving the **live** `id.research.greentic.cloud` OIDC issuer off the Cloudflare
Worker/D1 path onto the native-`serve` container on the shared ap-southeast-1
estate, backed by external Supabase Postgres. designer-admin depends on this
issuer for auth, so this is a **production cutover** — follow the order, keep the
rollback ready.

## Key differences from `develop`
- **ALWAYS-ON**, not scale-to-zero: `desired_count = 1`, `min_capacity = 1`
  (`examples/research.answers.json`). A scaled-to-zero issuer would break
  designer-admin login.
- Uses the **research** Supabase and the **research** master key. The signing
  keys migrated into Supabase are sealed under that master key — validated
  2026-07-23: `GET /jwks.json` unseals the migrated `encrypted_private_jwk`
  correctly, so token signing works on Supabase.

## Pre-req: secrets in Secrets Manager (ap-southeast-1)
```bash
# Research master key — the EXACT key the Worker uses (wrangler secret, write-only;
# you must supply the recorded value). Do NOT generate a new one, or the migrated
# sealed signing keys / worker_secrets become unreadable.
aws secretsmanager create-secret --name tm-research-master-key \
  --secret-string 'RESEARCH_MASTER_KEY' --region ap-southeast-1
aws secretsmanager create-secret --name tm-research-platform-hash \
  --secret-string 'sha256:RESEARCH_PLATFORM_HASH' --region ap-southeast-1
aws secretsmanager create-secret --name tm-research-db-url \
  --secret-string 'postgresql://postgres:PASS@db.rvjfxljplrnrndymikuc.supabase.co:5432/postgres?sslmode=require' \
  --region ap-southeast-1
```
> **Rotate first if the values were ever exposed.** Platform hash + worker
> secrets can be rotated freely. The master key cannot be rotated without
> re-sealing all signing keys / worker_secrets — plan a re-seal if needed.

## Cutover steps (each with a checkpoint)

### 1. Build + push the image
`deploy-develop.yml` (tenant-manager) `action: build` → digest-pinned ECR image.
Put the digest in `image_uri` in `examples/research.answers.json`. Pick a
`listener_rule_priority` NOT already used on the shared ALB
(`aws elbv2 describe-rules --listener-arn <shared-listener>`; research uses 90).

### 2. Deploy the ECS service (still on D1 for live traffic)
```bash
greentic-deployer aws generate --tenant research --provider-pack dist/tenant-manager-aws.gtpack --answers examples/research.answers.json
greentic-deployer aws plan     --tenant research --provider-pack dist/tenant-manager-aws.gtpack --answers examples/research.answers.json
greentic-deployer aws apply    --tenant research --provider-pack dist/tenant-manager-aws.gtpack --answers examples/research.answers.json
```
The ECS service (`greentic-tm-research`) comes up healthy on the ALB against the
point-in-time Supabase copy, **without any DNS pointing at it yet**. Live traffic
still hits the Worker/D1.
**Checkpoint:** hit the ALB target directly (Host header
`id.research.greentic.cloud`): `/healthz` 200, `/jwks.json` returns the real
keys, a test `/oauth/authorize`→`/oauth/token` signs.

### 3. Freeze + final delta sync
The migrated Supabase copy is a point-in-time snapshot; D1 has taken live writes
since. Just before switching:
- **Freeze D1 writes** — put the Worker in a read-only/maintenance posture (or
  accept a short write-freeze window; logins are read-mostly).
- **Final export** `wrangler d1 export gtm-prod -c wrangler.research.toml --remote`
  and load the delta into Supabase (same migrate script used for the first copy;
  it is INSERT-based, so pre-existing rows conflict — either target only new rows
  or `TRUNCATE`+reload the mutable tables: sessions, refresh_tokens,
  oidc_authorization_codes, passkey_login_states, audit_events, rate_limit_events).
  Immutable-ish tables (tenants, users, passkey_credentials, oidc_clients,
  did_key_metadata) rarely change — verify counts match D1 before proceeding.
**Checkpoint:** Supabase row counts == D1 row counts for the key tables.

### 4. Repoint DNS
Switch `id.research.greentic.cloud` from the Cloudflare Worker route to the ALB
(Route53 ALIAS, or the CNAME/route wherever the name is authoritative). TTL low
first so rollback is fast.
**Checkpoint:** `curl https://id.research.greentic.cloud/jwks.json` resolves to
the ALB and returns the keys; a real designer-admin SSO login end-to-end works.

### 5. Verify live, then decommission
- Watch designer-admin login + token introspection for one cycle.
- Keep the Worker/D1 deployed and the DNS rollback ready for 24–48h.
- Only after stable: remove the Worker route (leave D1 as a cold backup for a
  while).

## Rollback (any checkpoint fails)
- **Before step 4:** nothing live changed — `terraform destroy` the research
  stack (or leave it idle) and investigate. Zero user impact.
- **After step 4:** repoint DNS back to the Worker (low TTL makes this fast). The
  Worker/D1 is untouched and authoritative. Then unfreeze / re-sync as needed.

## Then: replicate to develop
develop's infra is already merged; apply it the same way with
`examples/develop.answers.json` (scale-to-zero, its own Supabase). develop is
non-live, so no freeze/DNS-repoint ceremony — just apply and `scale-up` to test.
