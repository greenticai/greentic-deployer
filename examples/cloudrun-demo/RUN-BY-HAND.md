# Cloud Run by hand — no script

`demo.sh` narrates. This is the same thing as **nine commands you type yourself**,
with an explanation of what each one is for and what it does *not* do. Set your
project in step 0 and every block below is copy-pasteable verbatim — there is
nothing left to hand-edit, and no script to run.

> **Every command here was executed against a real project on 2026-07-17**
> (a personal project in `europe-west1`), **in fish**, and the output
> below is the real output, trimmed. ~46 s from `env up` to a live URL. The
> deployed bundle serves a **browser webchat GUI** (verified live — SPA loads,
> DirectLine mints a token, the bot answers with an Adaptive Card) and, when you
> seed a token, a **Telegram** provider (token staging verified live 2026-07-17
> with a manual `setWebhook`).
>
> **Updated 2026-07-20:** the pinned runtime image now **self-registers** the
> Telegram webhook (no `setWebhook` — greentic-start PR #416, §7.5). That path is
> covered by unit + mutation tests but a live Cloud Run round-trip of the
> self-registration is still owed; the demo keeps a manual fallback so it works
> regardless.

The whole thing is really *one* command (step 6). Steps 1–5 are a one-time setup
you will never repeat, and steps 7–9 are verification and cleanup.

### Shell

Written for **fish** (4.8). Only three things here differ from bash/zsh, because
modern fish takes `$(...)`, `&&`, `||`, and even `VAR=value cmd` prefixes just
fine. The differences, all tested:

| | fish | bash / zsh |
|---|---|---|
| write a file | `echo '…' > f` | heredoc `cat > f <<'EOF'` — **fish has no heredocs** |
| set a variable | `set URL (cmd)` | `URL=$(cmd)` — **fish rejects bare `=`** |

Fish tells you both, clearly:

```console
> URL=https://x.example
fish: Unsupported use of '='. In fish, please use 'set URL https://x.example'.
> cat > f.txt <<'EOF'
fish: Expected a string, but found a redirection
```

`set URL $(cmd)` also works in fish 4.x, but `set URL (cmd)` is the idiom.
Everything else below is identical in both shells.

---

## 0. Set your project once, then copy-paste the rest verbatim

Every command below uses these variables — there is **no placeholder to hand-edit**
anywhere past this block. Set them once per shell and nothing else needs touching:

```fish
set -x PROJECT   your-gcp-project-id
set -x REGION    europe-west1
cd examples/cloudrun-demo                     # or any empty dir you like
```

<details><summary>bash / zsh</summary>

```bash
export PROJECT=your-gcp-project-id
export REGION=europe-west1
cd examples/cloudrun-demo
```
</details>

`$URL` and `$SVC` get set for you by step 6. `$TELEGRAM_BOT_TOKEN` is only needed
if you want Telegram (§5.5) — leave it unset to run webchat-only.

## 1. Install a deployer that can actually do Cloud Run

```fish
cargo binstall greentic-deployer-dev
```

**Why `-dev` and not `gtc`.** The Cloud Run deployer is a Cargo feature,
`deploy-gcp-cloudrun`. It is a *default* feature, but it is only on the `develop`
lane — a stable `gtc` or `greentic-deployer` has no Cloud Run deployer compiled in
at all. On the develop lane, binary-shipping crates publish under a sibling
`-dev` name (binary bifurcation), so `greentic-deployer-dev` is the develop build
of the same binary. Verified: `1.2.29582984900` has the feature.

Two traps:

- **`gtc op` is not this binary.** `gtc op …` delegates to `greentic-operator`, a
  *different* crate on its own release cadence. It picks up the deployer's default
  features, so Cloud Run will ride along automatically once a stable release
  carries it — but today's `greentic-operator 1.1.4` does not have it.
- **`--version` cannot tell you which dev build you have.** It prints
  `greentic-deployer 1.2.0-dev.0` for every nightly; the run-id lives only in the
  crates.io version. So **a stale `greentic-deployer-dev` looks identical to a
  current one.** The copy already on this machine was a June 27 build that
  reported `1.1.0-dev.0` and had no Cloud Run deployer — and no `op env up`
  either. If anything below fails oddly, re-run the binstall first.

Confirm the build can really do Cloud Run before you trust it. `--help` will not
tell you (see `README.md`); only `env doctor` resolves the binding against the
handler registry:

```fish
set S (mktemp -d)
greentic-deployer-dev op --store-root $S --answers cloudrun.env.json env apply --yes >/dev/null
greentic-deployer-dev op --store-root $S env doctor local | python3 -m json.tool | grep -A1 unknown_kinds
rm -rf $S
#   "unknown_kinds": [],          ← good
#   "unknown_kinds": ["greentic.deployer.gcp-cloudrun@1.0.0"]   ← no Cloud Run in this build
```

That writes to a throwaway store and makes no cloud calls. (Do it *after* step 5
— it needs the manifest.)

If you want to install without touching your `gtc install`-managed `~/.cargo/bin`:

```fish
cargo binstall --root /tmp/gtc-dev greentic-deployer-dev
# → /tmp/gtc-dev/bin/greentic-deployer-dev
```

## 2. Point gcloud at your project and log in

```fish
gcloud config set project $PROJECT
gcloud auth application-default login
```

**What ADC is for.** The deployer does not take a `--key-file`; it runs as the
**ambient Application Default Credentials** chain — the same identity
`gcloud auth application-default login` writes to
`~/.config/gcloud/application_default_credentials.json`. On a personal project you
are the owner, so that identity already has every permission the deploy needs.

Check it without deploying anything:

```fish
gcloud config get-value project
gcloud auth application-default print-access-token >/dev/null && echo "ADC OK"
```

> `gcloud auth login` (without `application-default`) authenticates the *CLI*, not
> your code. They are separate credential stores. You need both.

## 3. Enable the four APIs

```fish
gcloud services enable \
  run.googleapis.com \
  secretmanager.googleapis.com \
  artifactregistry.googleapis.com \
  logging.googleapis.com \
  --project $PROJECT
```

- `run` — create the Service and its revisions.
- `secretmanager` — the seed (the environment document the container boots from).
- `artifactregistry` — needed for the *API surface* even though this demo creates
  no repo; the image and bundle both come from public GHCR.
- `logging` — so `gcloud logging read` works when a boot fails.

Enabling an API costs nothing. They stay enabled after cleanup (see §10).

## 4. Create the runtime service account

```fish
gcloud iam service-accounts create gtc-local-runtime \
  --display-name "Greentic runtime for env local" \
  --project $PROJECT
```

**This is the identity the container runs as** — not the identity that deploys.
The deployer deliberately creates **neither** service account itself; it renders
Terraform for you to review and apply (`op credentials bootstrap`). On a personal
project where you are owner, you don't need that Terraform: the *deployer's*
permissions are already yours via ADC, and this SA is the only thing that must
exist.

**Grant it nothing.** It needs no project-level role. The one permission it needs
— reading the seed secret — is bound **on the secret itself** at deploy time,
automatically. Verified after a real run:

```console
$ gcloud projects get-iam-policy $PROJECT \
    --flatten="bindings[].members" \
    --filter="bindings.members:gtc-local-runtime" --format="table(bindings.role)"
                                     # ← empty. Zero project-level roles.
```

That is the design: resource-scoped, not project-scoped. Naming is
`gtc-{env_id}-runtime@{project}.iam.gserviceaccount.com`, so env `local` →
`gtc-local-runtime`.

## 5. Write the manifest

One file describes the whole environment. `env up` consumes a
`greentic.env-manifest.v1` document — **not** a bag of answers.

**fish has no heredocs.** Use a single-quoted multi-line string instead — fish
takes newlines inside quotes, and single quotes stop it interpreting anything.
Single quotes also mean `$PROJECT` would *not* expand, so the two variable slots
are written as `@@…@@` markers and substituted by `sed` on the way out. This form
is byte-identical in fish, bash, and zsh — paste it into any of them:

```fish
echo '{
  "schema": "greentic.env-manifest.v1",
  "environment": { "id": "local", "name": "cloudrun-byhand" },
  "trust_root": "bootstrap",
  "packs": [
    { "slot": "deployer",
      "kind": "greentic.deployer.gcp-cloudrun@1.0.0",
      "pack_ref": "builtin",
      "answers": {
        "project": "@@PROJECT@@",
        "region": "@@REGION@@",
        "access_mode": "public",
        "runtime_image_digest": "sha256:c122d86143293afec4389dbb57e4a8e9510849a0dd548207acd3892d63582920"
      } },
    { "slot": "secrets", "kind": "greentic.secrets.dev-store@1.0.0", "pack_ref": "builtin" }
  ],
  "bundles": [
    { "bundle_id": "cloudrun-byhand",
      "bundle_source_uri": "oci://ghcr.io/greenticai/greentic-demo-bundles/webchat-bot:webchat-tg-v1",
      "bundle_digest": "sha256:7608e322abf305172e20f7bab0607a36c0b0cc09c1d6869c7e5ba7ebfc094c47",
      "route_binding": { "path_prefixes": ["/"] } }
  ]
}' | sed -e "s|@@PROJECT@@|$PROJECT|" -e "s|@@REGION@@|$REGION|" > cloudrun.env.json

python3 -m json.tool cloudrun.env.json | grep -E '"(project|region)"'
```

That last line is the check — it must print your real project and region, not the
markers:

```console
        "project": "my-gcp-project",
        "region": "europe-west1",
```

(If it prints `@@PROJECT@@`, you skipped step 0. It also fails as JSON if the
`echo` got mangled, so it doubles as the syntax check.)

Line by line:

- **`packs[deployer]`** — which deployer to use. `kind` selects the Cloud Run
  handler; `answers` are its entire config. Three keys, everything else defaults.
  There is **no cluster block** — Cloud Run has no cluster.
- **`access_mode: "public"`** — grants `allUsers` → `roles/run.invoker`, so the
  URL is reachable without a token. Use `"authenticated"` and callers need an
  identity token. Note `public` also exposes `/status` and `/readyz`.
- **`runtime_image_digest`** — pins the **container image** (the greentic-start
  runtime) by digest. Load-bearing twice over: the deployer otherwise defaults to
  the moving `:develop` tag, which Cloud Run caches ~1h and which can resolve to a
  build too old to (a) serve the webchat SPA — the browser chat then 405s — or
  (b) self-register the Telegram webhook (§7.5). This digest is develop @
  2026-07-20 (`greentic-start-distroless:develop-4e6a414`, greentic-start PR
  #416), which carries both. Bump it to a newer digest with:
  ```fish
  gh api /orgs/greenticai/packages/container/greentic-start-distroless/versions \
    --jq '.[] | select(.metadata.container.tags[]?=="develop") | .name'
  ```
- **`packs[secrets]`** — the dev-store. Fine for a demo; use Vault for real work.
  It is where the Telegram bot token is written (§5.5) — staged into the seed.
- **`bundle_source_uri`** — must be an **OCI URI, not a local path**. Cloud Run
  pulls the bundle over the network *at container boot*; a `bundle_path` on your
  laptop is meaningless to it. This URI rides inside the seeded environment
  document, not as an env var. This bundle (`webchat-tg-v1`) carries three packs:
  the bot flow, `messaging-webchat-gui` (the browser SPA), and `messaging-telegram`.
- **`bundle_digest`** — pins the content. A tag is moving and Cloud Run caches
  tags; the digest is what makes the boot reproducible.
- **`route_binding.path_prefixes: ["/"]`** — this bundle serves everything.

## 5.5 (optional) Telegram — declare the token in the manifest

Skip this whole section to run webchat-only. To also wire the Telegram provider
that ships in this bundle, add a `secrets` block to the manifest and export the
token as an env var. `env up` reads it at apply time, writes it to the per-env
dev-store, and stages that into the Cloud Run seed — **all in the one command in
step 6.** No separate `secrets put`, no temp file: the manifest names the env var,
never the value.

Add this top-level `"secrets"` array to the `cloudrun.env.json` you wrote in
step 5 (a sibling of `packs`/`bundles`):

```json
  "secrets": [
    { "path": "default/_/messaging-telegram/telegram_bot_token",
      "from_env": "TELEGRAM_BOT_TOKEN" }
  ],
```

Then export the token before step 6 — put it in your shell, never in the file:

```fish
set -x TELEGRAM_BOT_TOKEN 123456:your-token-here
```

- **`from_env` names the env var; the value never enters the manifest.** `env up`
  resolves `$TELEGRAM_BOT_TOKEN` at apply time. If the var is unset on a mutating
  run, `env up` treats it as a *missing input* and refuses — that's why the block
  is opt-in, not always present. (On a TTY with the var unset it prompts, masked.)
- **The `path` is `<tenant>/<team>/<pack>/<name>` = `default/_/messaging-telegram/telegram_bot_token`.**
  `_` is the default team (a literal `default` team is rejected). The runtime reads
  `secrets://local/default/_/messaging-telegram/telegram_bot_token` — verified from
  the container logs, so this key is not a guess.
- **`bot_token` is the config field; `telegram_bot_token` is the store key.** The
  `path` names the store key.
- The value is decrypted only inside the runtime; `op secrets get` shows
  presence, not the value, unless you pass `reveal: true`.

That's it — run step 6 with the var exported and the token is seeded and staged
by the same `env up`.

<details><summary>The older two-step way (still works)</summary>

If you'd rather keep the token out of the manifest entirely, seed the store
directly. `secrets put` needs the store to exist, so create it first with
`env apply` (store-only, no cloud calls):

```fish
set -x TELEGRAM_BOT_TOKEN 123456:your-token-here
greentic-deployer-dev op --store-root ./state --answers cloudrun.env.json env apply --yes
echo '{"environment_id":"local","path":"default/_/messaging-telegram/telegram_bot_token","value":"'$TELEGRAM_BOT_TOKEN'"}' > /tmp/tgsec.json
greentic-deployer-dev op --store-root ./state secrets put --answers /tmp/tgsec.json
rm /tmp/tgsec.json
```
The manifest form above is preferred — one command, and the value never lands in
a file.
</details>

## 6. The one command

```fish
greentic-deployer-dev op --store-root ./state --answers cloudrun.env.json env up --yes
```

- `--store-root ./state` — where the environment lives locally. Omit it and it
  defaults to `~/.greentic/environments`. Keeping it local makes the demo
  self-contained and disposable.
- `--answers` — the manifest from step 5. (It is a global flag, so it goes
  **before** `env up`, not after.)
- `--yes` — skip the confirmation prompt.

Real output (~46 s):

```console
[1/6] ensure-environment     local            create…
[2/6] update-host-config     local            create…
[3/6] bootstrap-trust-root   local            create…
[4/6] update-pack-binding    deployer         update…
[5/6] update-pack-binding    secrets          update…
[6/6] deploy-bundle          cloudrun-byhand  create…
{"noun":"env","op":"up","result":{
  "applied_splits":1,
  "endpoint_url":"https://gtc-svc-01kxr5arxfhjay9krstpnrp99t-pyd2wo4g2a-ew.a.run.app",
  "endpoints":[{"deployment_id":"01KXR5ARXFHJAY9KRSTPNRP99T","url":"https://…"}],
  "environment_id":"local",
  "kind":"greentic.deployer.gcp-cloudrun@1.0.0",
  "warmed":["gtc-svc-01kxr5arxfhjay9krstpnrp99t"]}}
```

`endpoint_url` is the convenience field for the single-deployment case;
`endpoints[]` is the general one. The URL was **assigned by Cloud Run and rode
back on the deploy response** — there is no second API call to discover it. The
service is named `gtc-svc-{deployment_ulid}`.

**Capture the URL and the service name** — every step after this uses them. The
progress lines go to **stderr** and the JSON envelope to **stdout**, so redirecting
stdout to a file still lets you watch the plan scroll by:

```fish
greentic-deployer-dev op --store-root ./state --answers cloudrun.env.json env up --yes > up.json

set -x URL (python3 -c "import json;print(json.load(open('up.json'))['result']['endpoint_url'])")
set -x SVC (python3 -c "import json;print(json.load(open('up.json'))['result']['warmed'][0])")
echo "$URL  ($SVC)"
```

<details><summary>bash / zsh</summary>

```bash
greentic-deployer-dev op --store-root ./state --answers cloudrun.env.json env up --yes > up.json

export URL=$(python3 -c "import json;print(json.load(open('up.json'))['result']['endpoint_url'])")
export SVC=$(python3 -c "import json;print(json.load(open('up.json'))['result']['warmed'][0])")
echo "$URL  ($SVC)"
```
</details>

If you lose the shell, both are recoverable without redeploying:

```fish
set -x SVC (gcloud run services list --project $PROJECT --region $REGION --format='value(metadata.name)')
set -x URL (gcloud run services describe $SVC --project $PROJECT --region $REGION --format='value(status.url)')
```

(Re-running `env up` is idempotent — the plan comes back all `no-op` and you get
the same URL.)

## 7. Verify — "up" and "working" are different claims

```fish
curl -s -o /dev/null -w '%{http_code}\n' "$URL/readyz"      # → 200
curl -s "$URL/status" | python3 -m json.tool
```

```json
{
    "schema": "greentic.status.v1",
    "env_id": "local",
    "listen_addr": "0.0.0.0:8080",
    "bundles_active": 1,
    "deployments_routed": 1,
    "revisions_active": 1
}
```

**Use `/readyz`, never `/healthz`.**

```console
$ curl -s -o /dev/null -w '%{http_code}' $URL/healthz     # → 404  ← Google, not you
$ curl -s -o /dev/null -w '%{http_code}' $URL/readyz      # → 200
$ curl -s -o /dev/null -w '%{http_code}' $URL/livez       # → 200
$ curl -s -o /dev/null -w '%{http_code}' $URL/health      # → 200
```

Cloud Run's frontend **swallows `/healthz`** and answers it with Google's own
branded HTML 404 — the request never reaches your container. Every other path
arrives normally. You can prove who answered by looking at the headers: the
`/healthz` 404 has *no* `server` header, while a path that genuinely reaches the
container carries `server: Google Frontend`:

```console
$ curl -sD- -o /dev/null $URL/healthz | grep -iE '^(HTTP|server)'
HTTP/2 404                                    # ← no server header: Google answered
$ curl -sD- -o /dev/null $URL/nope | grep -iE '^(HTTP|server)'
HTTP/2 405
server: Google Frontend                       # ← reached the container, which 405'd
```

**And a 200 from `/readyz` still proves nothing.** It is a static route — it
answers 200 from a runtime that pulled no bundle and loaded nothing. `/status` is
the real check: `bundles_active` is non-zero only once the seed parsed, the bundle
pulled from GHCR, and its packs loaded. **`bundles_active: 0` next to a green
`/readyz` is the signature of a broken bundle reference**, and it is the failure
this demo is built to catch.

If it *is* 0, the container's own logs are the next stop:

```fish
gcloud logging read \
  "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"$SVC\"" \
  --project $PROJECT --limit 50 --freshness 1h
```

(Double quotes here, not single — the filter has to interpolate `$SVC`. The inner
quotes are part of the Logging query language, so they must survive as literals,
hence the backslashes. Identical in fish and bash.)

## 7.5 Chat with it — webchat GUI and Telegram

**Webchat GUI (browser).** Open the SPA — it is a **public** static route (served
with CORS, no login), backed by DirectLine:

```fish
echo "$URL/v1/web/webchat/default/"      # open this in a browser
```

A quick headless check that the runtime really serves it (200 + `text/html`; a
**405** means the image is too old — see `runtime_image_digest` in step 5):

```fish
curl -s -o /dev/null -w '%{http_code}\n' "$URL/v1/web/webchat/default/"     # → 200
```

The chat drives DirectLine under `/v1/messaging/webchat/default/…`: `POST …/token`
mints a session JWT, `POST …/v3/directline/conversations` opens a conversation,
and the bot answers with an Adaptive Card. All public, all from pack presence —
no endpoint registration needed.

**Telegram — the webhook registers itself.** If you seeded the token in §5.5,
you do **not** run `setWebhook`. On Cloud Run the runtime derives its own public
URL from the first inbound request's `Host` header — pinned to this service's own
`<name>-*.run.app` URL, so a forged Host can't hijack it (greentic-start PR #416)
— and calls the provider's `setup_webhook` for you. The `curl "$URL/status"` in
§7 above *was* that first request, so the webhook is already being registered
(asynchronously). Confirm it — the provider's ingress route is `/webhook/telegram`:

```fish
# getMe: token check + the bot's @username
curl -s "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/getMe" | python3 -m json.tool
# poll until the runtime has registered it (a few seconds):
curl -s "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/getWebhookInfo" | python3 -m json.tool
#   "url": "https://<name>-….run.app/webhook/telegram"   ← set by the runtime
```

Then message your bot — it replies through this deployment. No `setWebhook` call
anywhere.

> **Requires a runtime image with the self-registration (PR #416).** That is the
> `runtime_image_digest` pinned in step 5. On an older image the URL stays empty;
> then (and only then) register it by hand:
> ```fish
> curl -s "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/setWebhook" \
>   --data-urlencode "url=$URL/webhook/telegram" -d drop_pending_updates=true
> ```

> **The webhook is not cleaned up by `env destroy`** — it lives on Telegram's
> side, not in GCP. Clear it yourself when you tear down:
> ```fish
> curl -s "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/deleteWebhook"
> ```
> And **rotate the token in @BotFather** if it has been exposed.

## 8. See what exists

```fish
gcloud run services list --project $PROJECT --region $REGION
gcloud secrets list --project $PROJECT
```

```console
NAME
gtc-svc-01kxr5arxfhjay9krstpnrp99t     ← the Service
NAME
gtc-local-environment                  ← the seed: {secret_prefix}-environment
```

Exactly two things. That is the entire cloud footprint.

**Scale to zero:** leave it ~15 minutes with no traffic and the container count
drops to 0 — Console → Cloud Run → your service → METRICS → *Container instance
count*. No compute is billed at zero instances. The next request pays a cold start
(the container restarts and re-copies its seed). `min_instances=1` removes the
cold start and reintroduces a standing bill, which defeats the point of being here.

## 9. Destroy

```fish
greentic-deployer-dev op --store-root ./state env destroy local --confirm
```

```json
{"noun":"env","op":"destroy","result":{
  "environment_id":"local",
  "outcome":"destroyed",
  "provider_teardown":{
    "deleted_secrets":["gtc-local-environment"],
    "deleted_services":["gtc-svc-01kxr5arxfhjay9krstpnrp99t"],
    "skipped_secrets":[],
    "provider":"gcp-cloudrun","project":"…","region":"europe-west1"},
  "removed_path":"./state/local"}}
```

Note the ordering: **cloud resources are torn down before local state is removed**.
If teardown fails, the environment stays intact so you can retry — rather than
orphaning cloud resources you can no longer name. (`--force-local` purges local
state only and *does* orphan them; that is the escape hatch, not the happy path.)

---

## 10. So does it clean up everything? — honestly, no

`env destroy` removes **everything it created per run**. It does not remove the
one-time setup, and it was never meant to. Measured immediately after the destroy
above:

| | | |
|---|---|---|
| **Removed by `env destroy`** | Cloud Run Service `gtc-svc-…` | `Listed 0 items.` ✅ |
| | Secret `gtc-local-environment` | `Listed 0 items.` ✅ |
| | The secret's IAM binding | goes with the secret ✅ |
| | `allUsers` invoker binding | goes with the Service ✅ |
| | Local `./state/local` | ✅ |
| **Left behind** | SA `gtc-local-runtime@…` | step 4; **zero roles**, zero cost |
| | 4 enabled APIs | zero cost while unused |
| | Cloud Logging entries | ~30 days, free tier |
| | Local `./state/`, `cloudrun.env.json` | your files |
| **Never existed** | Artifact Registry repo | `Listed 0 items.` ✅ |

Verified with an independent sweep — not by trusting the destroy's own report:

```console
$ gcloud run services list --project $PROJECT --region $REGION   → Listed 0 items.
$ gcloud secrets list --project $PROJECT                         → Listed 0 items.
$ gcloud artifacts repositories list --project $PROJECT          → Listed 0 items.
$ gcloud iam roles list --project $PROJECT                       → Listed 0 items.
```

**Nothing bills after a destroy.** The leftovers are a service account with no
permissions and four enabled APIs — both free, and both exactly what you want to
keep if you will ever run this again.

**No Artifact Registry repo is ever created**, which is why standing storage cost
is zero: the worker image and the bundle are pulled straight from public GHCR. The
deployer never creates a repo — the `ar_repo` answer only *points at* one you
provisioned yourself, and setting it without provisioning first fails the pull.

To remove even the leftovers:

```fish
gcloud iam service-accounts delete gtc-local-runtime@$PROJECT.iam.gserviceaccount.com \
  --project $PROJECT --quiet
gcloud services disable run.googleapis.com secretmanager.googleapis.com \
  --project $PROJECT --force
```

Or just delete the whole project — the only way to be certain a cloud project
costs nothing is for it not to exist.

---

## The whole thing, minus the explanations

Fish, top to bottom, **nothing to hand-edit past the first two lines**. Steps 1–4
are once per project; after that it is two commands and a curl.

```fish
set -x PROJECT   your-gcp-project-id
set -x REGION    europe-west1

# ── once per machine / project ────────────────────────────────────────────
cargo binstall greentic-deployer-dev
gcloud config set project $PROJECT
gcloud auth application-default login
gcloud services enable run.googleapis.com secretmanager.googleapis.com \
  artifactregistry.googleapis.com logging.googleapis.com --project $PROJECT
gcloud iam service-accounts create gtc-local-runtime \
  --display-name "Greentic runtime for env local" --project $PROJECT

# ── the manifest (step 5 — full JSON is up there) ─────────────────────────
echo '{ … }' | sed -e "s|@@PROJECT@@|$PROJECT|" -e "s|@@REGION@@|$REGION|" > cloudrun.env.json

# ── every time ────────────────────────────────────────────────────────────
greentic-deployer-dev op --store-root ./state --answers cloudrun.env.json env up --yes > up.json
set -x URL (python3 -c "import json;print(json.load(open('up.json'))['result']['endpoint_url'])")
set -x SVC (python3 -c "import json;print(json.load(open('up.json'))['result']['warmed'][0])")

curl -s $URL/status | python3 -m json.tool     # bundles_active must be >= 1
echo "$URL/v1/web/webchat/default/"            # open the browser webchat GUI

greentic-deployer-dev op --store-root ./state env destroy local --confirm
```

For Telegram, add a `secrets` block to the manifest (§5.5) and export the token
before `env up` — no extra command, the same `env up` seeds it:

```fish
# in cloudrun.env.json, alongside packs/bundles:
#   "secrets": [ { "path": "default/_/messaging-telegram/telegram_bot_token",
#                  "from_env": "TELEGRAM_BOT_TOKEN" } ],
set -x TELEGRAM_BOT_TOKEN 123456:your-token-here
```

The runtime auto-registers the webhook once it's live (the `$URL/status` hit is
the trigger). Just confirm it, then delete it at teardown (which `env destroy`
cannot do):

```fish
curl -s "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/getWebhookInfo"   # url is set by the runtime
curl -s "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/deleteWebhook"    # at teardown
```

## See also

- `README.md` — the narrated `demo.sh` version of this, plus why a build without
  the Cloud Run deployer still prints a perfectly green plan.
- `greentic-deployer/docs/cloudrun-deployment.md` — the full reference: access
  modes, the seed contract, every config key, known gaps, troubleshooting.
- `greentic-deployer/tests/gcp_cloudrun_e2e.rs` — the automated version, plus a
  50/50 blue/green split and a traffic shift.
