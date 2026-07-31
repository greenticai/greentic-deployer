# Cloud Run demo — a digital worker that costs nothing while idle

One command puts a Greentic digital worker on **Google Cloud Run**, public, on a
real `https://….run.app` URL. When nobody is talking to it, it **scales to zero
and bills no compute**. You can talk to it two ways: a **browser webchat GUI**
at `<url>/v1/web/webchat/default/`, and (optionally) **Telegram**.

```bash
GCP_PROJECT=my-project GCP_REGION=europe-west1 ./demo.sh
# …with Telegram too:
TELEGRAM_BOT_TOKEN=123:abc GCP_PROJECT=my-project ./demo.sh
```

> **Status: VERIFIED LIVE — this script, start to finish, 2026-07-17.**
> Run against a real project (`europe-west1`): preflight → bootstrap → `env up`
> → `/readyz` 200 → `/status` `bundles_active: 1` → `env destroy`. Teardown
> reclaimed 1 Service + 1 secret, and an independent sweep afterwards
> (`gcloud run services list`, `secrets list`, `artifacts repositories list`)
> found **0 items** in all three — the zero-standing-cost claim is measured, not
> asserted. `greentic-deployer/tests/gcp_cloudrun_e2e.rs` covers the same flow
> plus a 50/50 blue/green split and passed live the same day.

## What it shows

| Step | What happens |
|---|---|
| 1. preflight | Checks your ADC identity and that the build has the Cloud Run deployer. |
| 2. bootstrap | Renders Terraform for the two service accounts + a minimum-privilege role. **You** apply it, once per project. |
| 3. `op env up` | One command, one JSON envelope, one live URL. |
| 4. verify | `/readyz` says it is *up*; `/status` proves it is *working*. |
| 4.5 chat | webchat GUI serves publicly; Telegram webhook registered (if a token was given). |
| 5. zero idle cost | What to look at, and what still bills. |
| 6. teardown | `op env destroy` reclaims every Service and secret. |

## Talking to it — webchat GUI and Telegram

The bundle carries three packs: the bot flow, `messaging-webchat-gui` (a browser
SPA), and `messaging-telegram`.

**Webchat GUI** is a **public** static route — `GET /v1/web/webchat/default/`
returns the SPA (served with CORS, no login), and it chats over DirectLine
(`POST /v1/messaging/webchat/default/token` → session JWT → conversation → the bot
answers with an Adaptive Card). All of it works **from pack presence alone** — no
messaging endpoint has to be registered. Two things have to be right, and both are
baked into this demo:

- **The runtime image must carry the SPA-serving code.** It landed on the develop
  lane on 2026-07-17; the manifest **pins `runtime_image_digest`** to that build.
  Leave it on the deployer's default `:develop` tag and Cloud Run's ~1h tag cache
  can hand you an older build whose webchat route 405s.
- **The webchat-gui pack must be recent (≥ 0.5.10).** Older packs didn't declare
  the `render_plan`/`encode`/`send_payload` egress ops, so the bot's reply was
  silently rejected by the runner's declared-ops allowlist — it loaded, but never
  answered. This bundle uses 0.5.10.

**Telegram** is opt-in. Export `TELEGRAM_BOT_TOKEN` (from @BotFather) and the demo
folds it into the manifest as an env-sourced **secret** (`from_env` — the manifest
names the var, never the value) so the single `env up` writes it to the dev-store
and stages it into the Cloud Run seed at `secrets://…/messaging-telegram/telegram_bot_token`
— never baked into the bundle or image. The webhook then **registers itself**: on
the first public request the runtime derives its own `<url>/webhook/telegram` from
the request Host (pinned to this service's `run.app` URL — greentic-start PR #416)
and calls `setup_webhook` — no manual `setWebhook`. Message the bot and it replies
through the deployment. (Self-registration needs the PR-#416 runtime image, which
is the pinned `IMAGE_DIGEST`; the demo falls back to a manual `setWebhook` if it's
not observed, and the self-registration path is not yet live-verified end-to-end.)
Two caveats: `env destroy` does **not** clear the Telegram-side webhook
(`.../deleteWebhook` does), and a token pasted anywhere should be **rotated in
@BotFather**.

## The interesting parts

**One file describes the environment.** `cloudrun.env.json.tmpl` → rendered to
`cloudrun.env.json`. No cluster block: there is no cluster. Deployer answers are
just `project`, `region`, `access_mode` — everything else defaults.

**A build without the Cloud Run deployer plans a perfect deploy anyway.** Found
by running this demo against a stable `1.1.16`, which has no Cloud Run deployer
compiled in at all. It does not say so:

| what you'd check | on a build that CANNOT deploy Cloud Run |
|---|---|
| `op env --help` | still lists `up` — it is the K8s/generic verb |
| `op env up --dry-run` | green 6-step plan, `kind → …gcp-cloudrun` |
| `op env apply --yes` | **exit 0**, `changed: 6`, `verify.failures: []` |
| `op env doctor` | `unknown_kinds: ["greentic.deployer.gcp-cloudrun@1.0.0"]` |

Three of the four happily plan and *bind* a deployer kind the binary cannot
execute. Only `doctor` resolves the binding against the handler registry, so it
is the only one that tells the truth — which is why the capability probe here
uses it, on a throwaway store.

**The probe fails closed, because its first cut didn't.** Asking only "does
`unknown_kinds` *contain* gcp-cloudrun?" passed a `1.1.0-dev.0` binary that has
no `op env up` at all: `doctor` never ran, the answer was empty, and empty is not
a match. An absent NO is not a YES. It now demands a parseable report whose
`bound_slots` includes `deployer` and whose `unknown_kinds` excludes cloudrun,
and refuses on anything else. Proven against three binaries: stale dev → *probe
could not run*; stable 1.1.16 → *unknown kind*; fresh dev → pass.

**A stale `greentic-deployer-dev` is the likeliest way to get bitten.** The dev
lane republishes under one name, so an old copy on your PATH looks current and
`--version` will not give it away (it says `1.2.0-dev.0` either way — the one on
this machine was a June 27 build reporting `1.1.0-dev.0`, with no Cloud Run at
all). Re-run `cargo binstall greentic-deployer-dev` if the probe complains.

**Use `/readyz`, not `/healthz`.** Verified live: Cloud Run answers `/healthz`
with Google's *own* 404 before it reaches your container — `/health`, `/livez`,
`/readyz` and `/status` all arrive normally. Nothing is wrong with the worker;
that one path is swallowed upstream.

**And a liveness 200 is not proof either.** `/readyz` is a static route; it
returns `200 ok` from a runtime that pulled no bundle and loaded nothing. The
demo asserts on `/status` (`bundles_active >= 1`), which is non-zero only once
the seeded environment parsed, the bundle pulled from GHCR, and its packs
loaded. `bundles_active: 0` next to a green `/readyz` is the signature of a
broken bundle reference.

**Nothing is cached in your project.** The worker image and the bundle are
pulled straight from **public GHCR** (both verified anonymously pullable), so no
Artifact Registry repo exists and no storage is billed. The deployer never
creates one: `ar_repo` only *points at* a repo you provisioned yourself, and
setting it without provisioning first fails the image pull.

**The zero-idle-cost claim is stated honestly.** Not "it costs nothing", but
*zero Cloud Run compute while idle, plus a short enumerated set of standing
charges* — in practice just the seed secret's active versions, a few cents a
month. The demo enumerates them rather than asserting the claim.

## Requirements

- A GCP project with **billing enabled**.
- A build with `deploy-gcp-cloudrun` (a **default** feature) — which today means
  the **develop lane**:
  ```bash
  cargo binstall greentic-deployer-dev     # verified 1.2.29582984900, has it
  ```
  A *stable* `gtc` / `greentic-deployer` does **not** have the Cloud Run deployer
  at all (checked 2026-07-17: `greentic-deployer 1.1.16` and `greentic-operator
  1.1.4` both lack it), so `gtc op env up` cannot deploy Cloud Run until a stable
  release carries it. `demo.sh` prefers `greentic-deployer-dev` for that reason,
  and the capability probe refuses up front rather than failing at dispatch.
  `GREENTIC_DEPLOYER_BIN=/path/to/build ./demo.sh` overrides it.

  > `greentic-deployer-dev --version` prints `greentic-deployer 1.2.0-dev.0`
  > whatever nightly you install — the run-id version lives only in the crates.io
  > name, so `--version` cannot tell you which dev build you have.
- `gcloud`, authenticated: `gcloud auth application-default login`.
- `tofu` or `terraform` — step 2 only, once per project.

## Flags

```bash
./demo.sh --dry-run    # plan only; never touches GCP, needs no credentials
./demo.sh --destroy    # tear down and exit
```

Overridable: `GCP_PROJECT`, `GCP_REGION`, `ACCESS_MODE` (`public` |
`authenticated`), `ENV_ID`, `STORE`, `BUNDLE_URI`, `BUNDLE_DIGEST`,
`IMAGE_DIGEST` (the pinned runtime image), `TELEGRAM_BOT_TOKEN` (enables the
Telegram provider), `GREENTIC_DEPLOYER_BIN`.

## Cleaning up

```bash
GCP_PROJECT=my-project ./demo.sh --destroy
```

Then confirm nothing is left:

```bash
gcloud run services list --project my-project --region europe-west1
gcloud secrets list --project my-project
```

Leaving it running is cheap-but-not-free: no compute is billed at zero
instances, but the seed secret still exists.

## See also

- `greentic-deployer/docs/cloudrun-deployment.md` — the full guide (access
  modes, the seed contract, the config reference, known gaps, troubleshooting).
- `greentic-deployer/tests/gcp_cloudrun_e2e.rs` — the automated version of this
  demo, plus a blue/green traffic split. `GREENTIC_GCP_E2E=1`.
