# Cloud Run demo — what's in here

A runnable, live-verified walkthrough of the `greentic.deployer.gcp-cloudrun`
path: one command puts a digital worker on Cloud Run, public, on a real
`https://….run.app` URL that scales to zero and bills no compute while idle.

Three ways in, same deployment:

| File | Use it when |
|---|---|
| [`demo.sh`](demo.sh) | You want it narrated and automatic. `GCP_PROJECT=… ./demo.sh` |
| [`RUN-BY-HAND.md`](RUN-BY-HAND.md) | You want to type the nine commands yourself and understand each one. fish and bash. |
| [`README.md`](README.md) | You want the pitch and the surprises found while building it. |
| [`site/index.html`](site/index.html) | You want a browsable page to share. Self-contained, no external requests. |
| [`cloudrun.env.json.tmpl`](cloudrun.env.json.tmpl) | The env-manifest `demo.sh` renders. |

```bash
./demo.sh --dry-run                      # plan only; touches no cloud, needs no credentials
GCP_PROJECT=my-project ./demo.sh         # the real thing
GCP_PROJECT=my-project ./demo.sh --destroy
```

## What it is not

Not a test. `tests/gcp_cloudrun_e2e.rs` is the automated version of the same
lifecycle (plus a blue/green split) and is what CI would run; this is the
human-readable counterpart.

## Keeping it honest

Every command in `RUN-BY-HAND.md` was executed against a real project and the
outputs shown are real, trimmed. Two consequences:

- **Pinned digests go stale.** The manifest pins `runtime_image_digest` and
  `bundle_digest` deliberately — Cloud Run caches moving tags for ~1h, and an
  older runtime image will fail in ways that look like your mistake (webchat
  405s, webhooks never register). When you refresh a pin, re-run the demo rather
  than assuming.
- **One caveat is stated rather than hidden.** The Telegram webhook
  self-registration has unit and mutation coverage but no live Cloud Run
  round-trip yet, so the walkthrough keeps a manual `setWebhook` fallback.

## See also

- [`docs/cloudrun-deployment.md`](../../docs/cloudrun-deployment.md) — the
  reference guide: access modes, the seed contract, config, known gaps.
- [`docs/cloudrun-internals.md`](../../docs/cloudrun-internals.md) — how the
  deployer is built, for changing it.
