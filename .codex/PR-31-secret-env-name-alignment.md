# PR-31 — Align the secret env-var name across the env bridge (finish PR-30)

## Why this exists
PR-29/PR-30 introduced the cloud env bridge: the deployer promotes runtime secrets
to the target cloud secret manager and surfaces them to `greentic-start` as
container env vars, until the runtime can consume secrets-provider bindings
("that env bridge is the current compatibility path and must remain until
greentic-start can consume provider bindings at runtime"). Investigation
(2026-06-30) found the bridge is **non-functional in cloud** because the three
sides do not agree on the env-var NAME, and the consumer the runtime actually
uses reads by the raw URI:

| Component | Env-var name scheme for `secrets://{env}/{tenant}/{team}/{cat}/{name}` |
|---|---|
| `greentic-secrets-lib::env::EnvSecretsManager` (**what greentic-start uses**) | `std::env::var(<raw secrets:// URI>)` — cannot be a real env var name |
| `greentic-secrets-core` env backend | `GTSEC_{ENV}_{TENANT}_{TEAM}_{CAT}_{NAME}` (sanitized, upper) |
| `greentic-deployer` runtime-secret canonical name | `GREENTIC_SECRET__{ENV}__{TENANT}__{TEAM}__{CAT}__{NAME}` |

Net: any env var the deployer injects is invisible to the runtime. Also note
`GREENTIC_SECRETS_BACKEND=env` only affects the **bundle-less serve path**
(`resolve_serve_secrets_manager`); the cloud container runs `start --bundle`,
whose `resolve_secrets_manager` selects the backend via a
`.providers/platform/secrets-provider.json` binding (`backend:"env"`), not that
env var.

## Already landed (prereqs)
- `greentic-types::env` — shared env-**id** resolution + `dev`→`local` alias
  (A4b), the single source of truth for the env segment. (greentic-types
  `feat/env-canonicalizer-a4b`.)
- Operator terraform sets `GREENTIC_SECRETS_BACKEND=env` + `GREENTIC_ALLOW_ENV_SECRETS=1`
  when `secrets_map` is non-empty, with the FIXME pointing here. (this branch.)
- Local runtime verified: develop `greentic-start` resolves `local` and DeepSeek
  answers via the dev-store; only the **cloud** env injection is missing.

## Goal
One shared **secret-env-name** function, used by both the producer (deployer)
and the consumer (runtime), so an injected secret env var is found.

## Scope
1. **greentic-types::env**: add `canonical_secret_env_var_name(uri) -> String`
   (one agreed scheme; recommend keeping the deployer's `GREENTIC_SECRET__…`
   shape or moving everyone to `GTSEC_…`). Unit-test against representative URIs.
2. **greentic-start**: wrap the `Env` backend so `read(secrets://…)` canonicalizes
   to `canonical_secret_env_var_name(uri)` before `std::env::var(...)` (today it
   passes the raw URI). Rebuild + republish the operator image.
3. **greentic-deployer**: emit the secret env var under the SAME name
   (`secrets_map`/`runtime_secret_env` keyed by the canonical name) AND generate
   `.providers/platform/secrets-provider.json` (`backend:"env"`) into the deployed
   bundle for cloud targets only (must NOT ship in the committed bundle — it would
   break local `gtc start`, which has no `GREENTIC_SECRET__…` vars).
4. **greentic-secrets-lib / -core**: align the two existing env schemes (or make
   `-lib` delegate to the shared fn) and deprecate the divergent one.
5. **Hygiene**: dedup the duplicated `dev`→`local` alias copies in
   `greentic-setup` and `greentic-start` onto `greentic-types::env`.
6. **Publish**: cut a develop `greentic.deploy.aws` (currently only `:stable` is
   published, and it lacks `runtime_secret_env`/`GREENTIC_SECRETS_BACKEND`).

## Secure target (beyond the bridge)
The bridge parks secrets in the process environment (visible process-wide / to
child components / exec / logs, fixed at boot). The end-state is a
secrets-provider binding that resolves `secrets://…` natively from AWS Secrets
Manager per-secret/just-in-time — needs an AWS SM secrets-provider pack shipped
in the bundle. Prefer this for production; keep the env bridge demo-only.

## Done when
A cloud deploy of deep-research (DeepSeek) resolves `api_key_secret` at runtime
and returns a real answer, with no secret in the bundle or Terraform state.
