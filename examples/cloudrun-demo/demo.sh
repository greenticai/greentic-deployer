#!/usr/bin/env bash
# Cloud Run demo — one command to a live, public, scale-to-zero digital worker.
#
#   The pitch: an idle Greentic environment on Cloud Run bills NO COMPUTE.
#   This script proves the whole claim end to end:
#
#     STEP 1  preflight            gcloud identity + the toolchain
#     STEP 2  bootstrap (once)     render Terraform → you apply it
#     STEP 3  gtc op env up        ONE command → a live https://….run.app URL
#     STEP 4  verify               /readyz says "up"; /status says "WORKING"
#     STEP 5  zero-idle-cost       what to look at, and what still bills
#     STEP 6  teardown             op env destroy reclaims everything
#
#   STATUS: VERIFIED LIVE end to end (2026-07-17, europe-west1) — this script,
#   not just the E2E test: /readyz 200, /status bundles_active=1, then destroy
#   reclaimed 1 Service + 1 secret with an independent gcloud sweep afterwards
#   finding 0 services, 0 secrets, 0 Artifact Registry repos.
#   tests/gcp_cloudrun_e2e.rs covers the same flow plus a 50/50 blue/green split.
#   Steps 1-2 and the teardown are safe to re-run; step 3 creates billable
#   (though scale-to-zero) resources.
#
#   That live run is also why step 4 probes /readyz and not /healthz — see below.
#
#   Requires:
#     gtc (or greentic-deployer) with the `deploy-gcp-cloudrun` feature — the
#       nightly `gtc-dev` / `greentic-deployer-dev` binaries ship it by default.
#     gcloud            — for ADC login + the read-only verification queries.
#     tofu OR terraform — step 2 only, once per project.
#
#   Usage:
#     GCP_PROJECT=my-project GCP_REGION=europe-west1 ./demo.sh          # full run
#     GCP_PROJECT=… ./demo.sh --dry-run     # plan only; never touches GCP
#     GCP_PROJECT=… ./demo.sh --destroy     # tear down and exit
#
#   The deployed bundle serves a browser WEBCHAT GUI at
#   <url>/v1/web/webchat/default/ (public, DirectLine-backed). To also enable the
#   Telegram provider, export your BotFather token first — it is seeded as a
#   runtime secret and the webhook is registered automatically, never baked in:
#     TELEGRAM_BOT_TOKEN=123:abc GCP_PROJECT=my-project ./demo.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STORE="${STORE:-$HERE/state}"
ENV_ID="${ENV_ID:-local}"
GCP_PROJECT="${GCP_PROJECT:-}"
GCP_REGION="${GCP_REGION:-europe-west1}"
ACCESS_MODE="${ACCESS_MODE:-public}"

# The public demo bundle: anonymously pullable from GHCR, so Cloud Run needs no
# registry credential and no Artifact Registry repo has to exist (that is what
# keeps standing storage cost at zero). Digest-pinned — a tag is moving and Cloud
# Run caches tags for ~1h.
#
# This bundle carries three packs: the bot flow, the `messaging-webchat-gui` SPA
# (browser chat at /v1/web/webchat/default/), and `messaging-telegram`.
BUNDLE_URI="${BUNDLE_URI:-oci://ghcr.io/greenticai/greentic-demo-bundles/webchat-bot:webchat-tg-v1}"
BUNDLE_DIGEST="${BUNDLE_DIGEST:-sha256:7608e322abf305172e20f7bab0607a36c0b0cc09c1d6869c7e5ba7ebfc094c47}"

# The runtime container image, pinned by digest. This MUST be a build that carries
# the webchat SPA + DirectLine serving code AND the Cloud Run webhook
# self-registration (greentic-start PR #416, develop 2026-07-20). The deployer
# otherwise defaults to the moving `:develop` tag, which Cloud Run caches for ~1h
# and which can resolve to a build too old to serve the SPA (405) or to
# self-register the Telegram webhook. This digest is develop @ 2026-07-20
# (greentic-start-distroless :develop-4e6a414). Bump it to a newer digest when you
# like — look it up with:
#   gh api /orgs/greenticai/packages/container/greentic-start-distroless/versions \
#     --jq '.[] | select(.metadata.container.tags[]?=="develop") | .name'
IMAGE_DIGEST="${IMAGE_DIGEST:-sha256:c122d86143293afec4389dbb57e4a8e9510849a0dd548207acd3892d63582920}"

# OPTIONAL Telegram provider. Export TELEGRAM_BOT_TOKEN (from @BotFather) to seed
# it as a runtime secret. On Cloud Run the runtime AUTO-REGISTERS the webhook on
# the first public request (no manual setWebhook) — see STEP 4.5. NEVER hard-code
# the token here or bake it into the bundle/image — it is staged into the per-env
# secret store at deploy time only. Leave unset to run webchat-only.
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"

cr_install_hint() {
  note "\`deploy-gcp-cloudrun\` is a DEFAULT feature, but it is on develop only."
  note "Install the develop-lane binary, which carries it:"
  note "  cargo binstall greentic-deployer-dev     # verified 1.2.29582984900"
  note "NOTE: an OLD greentic-deployer-dev on your PATH does NOT have it, and"
  note "\`--version\` always says 1.2.0-dev.0 — re-run binstall to be sure."
  note "Or point the demo at a build of your own:"
  note "  GREENTIC_DEPLOYER_BIN=/path/to/greentic-deployer ./demo.sh"
}

say()  { printf '\n\033[1;36m▸ %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; }
note() { printf '  \033[2m%s\033[0m\n' "$*"; }
die()  { bad "$*"; exit 1; }

DRY_RUN=0
DESTROY_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --destroy) DESTROY_ONLY=1 ;;
    *) die "unknown flag: $arg (want --dry-run | --destroy)" ;;
  esac
done

# `gtc op …` and `greentic-deployer op …` are the same surface; prefer gtc.
# (`gtc op` actually delegates to `greentic-operator`, which depends on the
# deployer with its DEFAULT features — so `deploy-gcp-cloudrun` rides along and
# no operator-side flag is needed. Confirmed in greentic-operator/Cargo.toml.)
# GREENTIC_DEPLOYER_BIN points the demo at a build of your own — necessary while
# the Cloud Run deployer is on develop and has not reached a released binary.
if [ -n "${GREENTIC_DEPLOYER_BIN:-}" ]; then
  [ -x "$GREENTIC_DEPLOYER_BIN" ] || die "GREENTIC_DEPLOYER_BIN is not executable: $GREENTIC_DEPLOYER_BIN"
  OP_BIN=("$GREENTIC_DEPLOYER_BIN" op)
# `greentic-deployer-dev` is the develop lane's binstall name (binary bifurcation).
# It is preferred over `gtc` ONLY because the Cloud Run deployer has not reached a
# stable release yet — a released `gtc`/`greentic-deployer` still has no Cloud Run
# deployer at all. DROP THIS BRANCH once a stable release carries it; the
# capability probe below is what actually decides, so the order is a convenience.
elif command -v greentic-deployer-dev >/dev/null 2>&1; then OP_BIN=(greentic-deployer-dev op)
elif command -v gtc >/dev/null 2>&1; then          OP_BIN=(gtc op)
elif command -v greentic-deployer >/dev/null 2>&1; then OP_BIN=(greentic-deployer op)
else die "no deployer on PATH — run: cargo binstall greentic-deployer-dev"; fi
OP=("${OP_BIN[@]}" --store-root "$STORE")

# ── STEP 6 (defined early so --destroy can jump straight to it) ─────────────
destroy() {
  say "STEP 6 — teardown: reclaim every Cloud Run Service + staged secret"
  note "The deployer tears down provider resources BEFORE removing local state,"
  note "so a failure here leaves the env intact to retry rather than orphaning"
  note "cloud resources you can no longer name."
  if "${OP[@]}" env destroy "$ENV_ID" --confirm; then
    ok "destroyed"
    note "Verify nothing is left (both should be empty of this env's resources):"
    note "  gcloud run services list --project $GCP_PROJECT --region $GCP_REGION"
    note "  gcloud secrets list --project $GCP_PROJECT"
  else
    bad "destroy failed — the env is still intact; fix the cause and re-run"
    note "If this build cannot tear Cloud Run down, it REFUSES rather than"
    note "orphaning. --force-local purges local state only, leaving the cloud"
    note "resources for you to delete by hand."
    return 1
  fi
}

if [ "$DESTROY_ONLY" = 1 ]; then
  [ -n "$GCP_PROJECT" ] || die "set GCP_PROJECT=<your-project>"
  destroy; exit $?
fi

# ── STEP 1 — preflight ──────────────────────────────────────────────────────
say "STEP 1 — preflight"
[ -n "$GCP_PROJECT" ] || die "set GCP_PROJECT=<your-project> (billing must be enabled)"
ok "project: $GCP_PROJECT   region: $GCP_REGION   access_mode: $ACCESS_MODE"

ok "deployer CLI: ${OP_BIN[0]} ($("${OP_BIN[0]}" --version 2>/dev/null | head -1))"

if [ "$DRY_RUN" = 0 ]; then
  # gcloud is not needed to DEPLOY (the deployer talks to the APIs directly),
  # but steps 2 and 5 use it to check the bootstrap landed and to enumerate what
  # still bills. Fail here rather than three steps in with a confusing error.
  command -v gcloud >/dev/null 2>&1 || {
    bad "gcloud not on PATH — needed to verify the bootstrap and the idle-cost claim"
    note "Arch/CachyOS: paru -S google-cloud-cli"
    note "Other:       https://cloud.google.com/sdk/docs/install"
    exit 1
  }
  ok "gcloud: $(gcloud version 2>/dev/null | head -1)"

  if [ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]; then
    ok "ADC: GOOGLE_APPLICATION_CREDENTIALS=${GOOGLE_APPLICATION_CREDENTIALS}"
  elif [ -f "$HOME/.config/gcloud/application_default_credentials.json" ]; then
    ok "ADC: gcloud application-default credentials"
  else
    bad "no Application Default Credentials found"
    note "The deployer runs as the AMBIENT ADC chain. Fix with either:"
    note "  gcloud auth application-default login"
    note "  export GOOGLE_APPLICATION_CREDENTIALS=/path/to/deployer-key.json"
    exit 1
  fi
fi

# ── The one file that describes the whole environment ───────────────────────
say "The manifest — one file, the whole environment"
mkdir -p "$STORE"
MANIFEST="$HERE/cloudrun.env.json"
sed -e "s|@@PROJECT@@|$GCP_PROJECT|g" \
    -e "s|@@REGION@@|$GCP_REGION|g" \
    -e "s|@@ACCESS_MODE@@|$ACCESS_MODE|g" \
    -e "s|@@BUNDLE_URI@@|$BUNDLE_URI|g" \
    -e "s|@@BUNDLE_DIGEST@@|$BUNDLE_DIGEST|g" \
    -e "s|@@IMAGE_DIGEST@@|$IMAGE_DIGEST|g" \
    -e "s|@@ENV_ID@@|$ENV_ID|g" \
    "$HERE/cloudrun.env.json.tmpl" > "$MANIFEST"
ok "rendered $MANIFEST"
note "$(grep -c . "$MANIFEST") lines. No cluster block — Cloud Run has no cluster."

# ── Fold the Telegram token into the manifest as an env-sourced secret ───────
# The manifest carries a `secrets[]` entry naming an ENV VAR (from_env), never
# the value. `env up` resolves $TELEGRAM_BOT_TOKEN at apply time and writes it to
# the dev-store — so the whole thing is ONE command, and the token value never
# lands in a file. Only inject when the token is set: an unset from_env is a
# "missing input" and a mutating env up refuses to run while any remain, so an
# unconditional block would break webchat-only runs.
if [ -n "$TELEGRAM_BOT_TOKEN" ]; then
  export TELEGRAM_BOT_TOKEN
  python3 - "$MANIFEST" <<'PY'
import json, sys
p = sys.argv[1]
m = json.load(open(p))
m.setdefault("secrets", []).append(
    {"path": "default/_/messaging-telegram/telegram_bot_token",
     "from_env": "TELEGRAM_BOT_TOKEN"}
)
json.dump(m, open(p, "w"), indent=2)
PY
  ok "manifest carries the Telegram secret (from_env: TELEGRAM_BOT_TOKEN — name only, no value)"
else
  note "TELEGRAM_BOT_TOKEN not set — deploying webchat-only (no Telegram provider)."
fi

# ── Capability probe — does THIS build actually HAVE the Cloud Run deployer? ──
# Nothing on the happy path tells you. Verified 2026-07-17 against a stable
# 1.1.16 build, which has no Cloud Run deployer at all:
#   `op env --help`      → still lists `up`   (it is the K8s/generic verb)
#   `env up --dry-run`   → prints a green 6-step plan, "kind → …gcp-cloudrun"
#   `env apply --yes`    → exit 0, changed: 6, verify.failures: []
# All three are happy to PLAN and BIND a deployer kind the binary cannot
# execute. `env doctor` is the only verb that resolves the binding against the
# handler registry, so it is the only one that tells the truth. Probed on a
# throwaway store: no cloud calls, no credentials, nothing left behind.
say "Capability probe — is the Cloud Run deployer compiled into this build?"
# This probe FAILS CLOSED. It demands positive proof (a parseable doctor report
# whose unknown_kinds excludes gcp-cloudrun) and refuses on anything else.
# The first cut asked only "does unknown_kinds CONTAIN gcp-cloudrun?" and so
# passed a 1.1.0-dev.0 binary that has no `env up` at all: doctor never ran, the
# answer was empty, and empty is not a match. An absent NO is not a YES.
PROBE_STORE="$(mktemp -d)"
"${OP_BIN[@]}" --store-root "$PROBE_STORE" --answers "$MANIFEST" env apply --yes >/dev/null 2>&1
VERDICT="$("${OP_BIN[@]}" --store-root "$PROBE_STORE" env doctor "$ENV_ID" 2>/dev/null | python3 -c '
import sys, json
try:
    r = json.load(sys.stdin)["result"]
except Exception:
    print("BROKEN"); raise SystemExit
unknown = r.get("unknown_kinds")
slots = r.get("bound_slots")
if unknown is None or slots is None:
    print("BROKEN")                                  # not the report we expected
elif any("gcp-cloudrun" in k for k in unknown):
    print("UNSUPPORTED " + ",".join(unknown))        # binary lacks the feature
elif "deployer" not in slots:
    print("BROKEN")                                  # manifest never bound
else:
    print("OK")                                      # positively confirmed
' 2>/dev/null)"
rm -rf "$PROBE_STORE"
case "$VERDICT" in
  OK) ok "gcp-cloudrun resolves against the handler registry (unknown_kinds: [])" ;;
  UNSUPPORTED*)
    bad "this build has NO Cloud Run deployer — env doctor calls it an unknown kind:"
    note "  unknown_kinds: [${VERDICT#UNSUPPORTED }]"
    note "It would still print a green plan and bind the pack, then fail at dispatch."
    cr_install_hint; exit 1 ;;
  *)
    bad "capability probe could not run against ${OP_BIN[0]} — refusing to guess."
    note "\`env apply\`/\`env doctor\` gave no usable report. Usually the build is far"
    note "too old: a 1.1.0-dev.0 deployer has no \`op env up\` at all."
    note "  $("${OP_BIN[0]}" --version 2>&1 | head -1)"
    cr_install_hint; exit 1 ;;
esac

if [ "$DRY_RUN" = 1 ]; then
  say "DRY RUN — plan only. This stops before the Cloud Run dispatch, so it"
  note "needs no credentials and creates nothing."
  "${OP[@]}" --answers "$MANIFEST" env up --dry-run
  exit $?
fi

# ── STEP 2 — bootstrap ──────────────────────────────────────────────────────
say "STEP 2 — bootstrap: the service accounts + the minimum-privilege role"
note "The deployer creates NEITHER service account. It renders Terraform that"
note "creates exactly what it needs — review it before applying."
"${OP[@]}" --answers "$MANIFEST" env apply --yes >/dev/null || die "env apply (store half) failed"
ok "deployer env-pack bound (store only — nothing sent to GCP yet)"

BS="$STORE/bootstrap.json"
cat > "$BS" <<JSON
{ "environment_id": "$ENV_ID",
  "admin_profile": "$(gcloud config get-value account 2>/dev/null || echo admin@example.com)",
  "admin_material_inline": "unused-by-the-gcp-renderer" }
JSON
TF_DIR="$STORE/$ENV_ID/rules/greentic.deployer.gcp-cloudrun"
if [ -f "$TF_DIR/gcp-cloudrun-bootstrap.tf" ]; then
  ok "bootstrap pack already rendered: $TF_DIR"
else
  "${OP[@]}" --answers "$BS" credentials bootstrap >/dev/null || die "credentials bootstrap failed"
  ok "rendered $TF_DIR/gcp-cloudrun-bootstrap.tf"
fi
note "It is RENDER-ONLY: no credential is minted and nothing was written to GCP."

SA="gtc-${ENV_ID}-runtime@${GCP_PROJECT}.iam.gserviceaccount.com"
if gcloud iam service-accounts describe "$SA" --project "$GCP_PROJECT" >/dev/null 2>&1; then
  ok "runtime service account exists: $SA"
else
  bad "runtime service account missing: $SA"
  note "Apply the bootstrap Terraform once per project, then re-run:"
  note "  cd $TF_DIR"
  note "  tofu init && tofu apply -var project_id=$GCP_PROJECT"
  exit 1
fi

# The Telegram token is already in the manifest (from_env, above), so `env up`
# seeds it into the dev-store and stages it into the Cloud Run seed in one shot —
# no separate `secrets put` step. The token never touches the bundle or the image.

# ── STEP 3 — the one command ────────────────────────────────────────────────
say "STEP 3 — gtc op env up: ONE command → a live URL"
OUT="$STORE/env-up.json"
"${OP[@]}" --answers "$MANIFEST" env up --yes | tee "$OUT" >/dev/null \
  || { bad "env up failed"; cat "$OUT"; exit 1; }
URL="$(python3 -c "import json;print(json.load(open('$OUT'))['result'].get('endpoint_url',''))" 2>/dev/null)"
[ -n "$URL" ] || { bad "env up returned no endpoint_url"; cat "$OUT"; exit 1; }
ok "live: $URL"
note "That URL was assigned by Cloud Run and rode back on the deploy response —"
note "no second API call to discover it."
ok "browser chat (webchat GUI): $URL/v1/web/webchat/default/"

# ── STEP 4 — verify ─────────────────────────────────────────────────────────
say "STEP 4 — verify: 'up' is not the same as 'working'"
# /readyz, NOT /healthz: verified live 2026-07-17 that Cloud Run answers
# /healthz with Google's own 404 before it ever reaches the container, while
# /health, /livez, /readyz and /status all arrive. See docs/cloudrun-deployment.md §7.
for i in $(seq 1 10); do
  code="$(curl -fsS -o /dev/null -w '%{http_code}' "$URL/readyz" 2>/dev/null || true)"
  [ "$code" = 200 ] && break
  note "cold start… ($i/10)"; sleep 3
done
[ "${code:-}" = 200 ] && ok "GET /readyz → 200" || { bad "GET /readyz → ${code:-no response}"; exit 1; }

note "But /readyz is a STATIC route — it answers 200 from a runtime that loaded"
note "nothing at all. /status is what proves the deploy actually worked:"
STATUS="$(curl -fsS "$URL/status" 2>/dev/null)"
echo "$STATUS" | python3 -m json.tool 2>/dev/null | sed 's/^/    /'
BUNDLES="$(echo "$STATUS" | python3 -c "import sys,json;print(json.load(sys.stdin).get('bundles_active',0))" 2>/dev/null || echo 0)"
if [ "${BUNDLES:-0}" -ge 1 ]; then
  ok "bundles_active=$BUNDLES — the seed parsed, the bundle pulled from GHCR, its packs loaded"
else
  bad "bundles_active=0 — booted, but loaded NO bundle"
  note "That is the signature of an unreachable bundle ref or a digest mismatch."
  note "  gcloud logging read 'resource.type=\"cloud_run_revision\"' --project $GCP_PROJECT --limit 50"
  exit 1
fi

# The webchat SPA is a PUBLIC static route (served with CORS, no loopback gate) —
# a 200 with text/html means the pinned runtime image really carries the serving
# code. A 405 here means the image is too old (see IMAGE_DIGEST above).
WC="$(curl -s -o /dev/null -w '%{http_code}' "$URL/v1/web/webchat/default/" 2>/dev/null || true)"
[ "$WC" = 200 ] && ok "webchat GUI serves (GET /v1/web/webchat/default/ → 200)" \
  || note "webchat GUI → $WC (405 ⇒ runtime image predates the SPA code; bump IMAGE_DIGEST)"

# ── STEP 4.5 — Telegram webhook (optional, auto-registered) ─────────────────
# The runtime SELF-REGISTERS the Telegram webhook on Cloud Run: on the first
# public request through Google's front end it derives its own public URL from
# the request Host (pinned to this service's <name>-*.run.app — see
# greentic-start PR #416) and calls the provider's setup_webhook op. The /status
# curl in STEP 4 was that first request, so no manual setWebhook is needed — the
# provider's ingress route is <prefix>/webhook/<provider-name> = /webhook/telegram.
# Registration is async (a deferred task), so we poll getWebhookInfo. If it never
# appears (e.g. the pinned image predates PR #416), we fall back to a manual
# setWebhook so the demo still works.
if [ -n "$TELEGRAM_BOT_TOKEN" ]; then
  say "STEP 4.5 — Telegram: the runtime auto-registers the webhook (no setWebhook)"
  HOOK="$URL/webhook/telegram"
  API="https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}"
  BOT="$(curl -fsS "$API/getMe" 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['username'])" 2>/dev/null || true)"
  [ -n "$BOT" ] && ok "token authenticates — bot is @$BOT"
  registered=""
  for i in $(seq 1 15); do
    info="$(curl -fsS "$API/getWebhookInfo" 2>/dev/null || true)"
    current="$(printf '%s' "$info" | python3 -c "import sys,json;print(json.load(sys.stdin).get('result',{}).get('url',''))" 2>/dev/null || true)"
    if [ "$current" = "$HOOK" ]; then registered=1; break; fi
    # Nudge: another public request guarantees the capture fired, then wait for
    # the async setup_webhook call to land.
    curl -s -o /dev/null "$URL/status" 2>/dev/null || true
    note "waiting for runtime auto-registration… ($i/15)"; sleep 3
  done
  if [ -n "$registered" ]; then
    ok "runtime auto-registered the webhook → $current (no manual setWebhook)"
  else
    note "auto-registration not observed after ~45s — falling back to manual setWebhook."
    note "(expected only if IMAGE_DIGEST predates greentic-start PR #416.)"
    if curl -fsS "$API/setWebhook" --data-urlencode "url=$HOOK" -d 'drop_pending_updates=true' >/dev/null 2>&1; then
      ok "webhook set manually → $HOOK"
    else
      bad "setWebhook failed — check TELEGRAM_BOT_TOKEN (BotFather)"
    fi
  fi
  [ -n "$BOT" ] && note "Message @$BOT on Telegram — it replies through this deployment."
  note "Teardown does NOT clear the webhook (it lives on Telegram's side). Remove it with:"
  note "  curl -s \"https://api.telegram.org/bot\$TELEGRAM_BOT_TOKEN/deleteWebhook\""
fi

# ── STEP 5 — the actual pitch ───────────────────────────────────────────────
say "STEP 5 — zero idle cost"
note "Leave it ~15 min with no traffic, then check the instance count flatten to 0:"
note "  Console → Cloud Run → gtc-svc-… → METRICS → Container instance count"
note ""
note "The honest claim is NOT 'it costs nothing'. It is:"
note "  zero Cloud Run COMPUTE while idle, plus a short, KNOWN set of standing"
note "  charges. Enumerate them — the point is the list is short:"
echo
gcloud secrets list --project "$GCP_PROJECT" 2>/dev/null | sed 's/^/    /' \
  || note "  (gcloud secrets list — the seed secret's active versions: a few cents/month)"
echo
if gcloud artifacts repositories list --project "$GCP_PROJECT" 2>/dev/null | grep -q .; then
  note "  Artifact Registry repos exist — those bill storage."
else
  ok "no Artifact Registry repositories — zero standing storage cost"
  note "(the image + bundle come straight from public GHCR. The deployer never"
  note " creates a repo; ar_repo only points at one you provisioned yourself,"
  note " which would then bill storage.)"
fi
note ""
note "The next request after idling pays a cold start: the container restarts and"
note "re-copies its seed. min_instances=1 trades that for a standing bill — which"
note "is a choice against the entire reason to be on Cloud Run."

# ── STEP 6 ──────────────────────────────────────────────────────────────────
echo
read -r -p "Tear it all down now? [y/N] " reply
case "$reply" in
  [yY]*) destroy ;;
  *) say "Left running (it scales to zero, so it bills no compute while idle)"
     note "URL:      $URL"
     note "Teardown: $0 --destroy" ;;
esac
