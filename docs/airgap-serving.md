# Airgap In-Gap Serving (Tier 2)

How to serve update plans and binary blobs to a fleet of machines inside
an air-gapped network from a single HTTP mirror, using the directory
layout produced by `greentic-deployer op updates import --push-to`.

> **Audience.** Operators who already import plans via USB sneakernet
> (Tier 1 -- see [airgap-quickstart.md](airgap-quickstart.md)) and want
> machines inside the gap to converge automatically without per-machine
> imports.

> **Commands below say `greentic-deployer` on purpose.** `gtc op ...`
> delegates to `greentic-operator`, a separate binary on its own release
> cadence.

---

## How Tier 2 differs from Tier 1

Tier 1 (the quickstart) moves a signed plan across the air gap onto one
receiving machine via USB. Every machine needs its own import.

Tier 2 adds a **single import point inside the gap** that serves the
whole in-gap fleet over HTTP. The gap crossing is still Tier 1
sneakernet -- nothing in this document crosses the air gap. The flow:

```
Staging side       USB / diode       Receiving side (mirror host)
────────────       ───────────       ────────────────────────────
export ──────────► .gtupdate ──────► import --push-to /srv/mirror
                                         │
                                         ▼
                                    HTTP file server
                                     ┌──────────┐
                                     │ /plan     │
                                     │ /blobs    │
                                     └──────────┘
                                         │
                          ┌──────────────┼──────────────┐
                          ▼              ▼              ▼
                       machine A     machine B     machine C
                     (greentic-start polls the mirror)
```

---

## Directory layout

`op updates import --push-to <DIR>` writes:

```
<DIR>/
  plan/
    plan.json        raw signed plan bytes
    plan.json.sig    DSSE envelope bytes
    meta             poll metadata (JSON: sequence + plan_sha256)
  blobs/
    sha256-<hex>     one file per content-addressed blob
  .push-lock         writer lock file (must NOT be served)
```

Files are written in dependency order: blobs first, then `plan.json`,
then `plan.json.sig`, then `meta` last. `meta` is the publish barrier
-- a reader that sees a new sequence in `meta` is guaranteed the plan
and blobs are already on disk.

Each file is written atomically (temp file, fsync, rename). Concurrent
imports to the same directory are serialized by `.push-lock`. Readers
never take the lock.

---

## Request contract

`greentic-start` polls a configured `plan_endpoint` (e.g.
`http://mirror.lan:8080/plan`). It makes four kinds of GET request.
Two need URL rewrites because the client requests `/plan` (a file) but
the directory on disk has `plan/` (a directory containing `plan.json`).

| Client request | Served file | Rewrite? |
|---|---|---|
| `GET {endpoint}/meta` | `plan/meta` | no |
| `GET {endpoint}` | `plan/plan.json` | **yes** |
| `GET {endpoint}.sig` | `plan/plan.json.sig` | **yes** |
| `GET {blob_url}/sha256-<hex>` | `blobs/sha256-<hex>` | no |

`{endpoint}` = `plan_endpoint`, `{blob_url}` = `blob_base_url`.

### Why the rewrites are needed

The path `/plan` cannot be both a file (for `GET /plan`) and a
directory (containing `meta` at `/plan/meta`). On disk it is a
directory, so without the rewrite:

- **`GET /plan`** returns **301 Moved Permanently** (nginx redirects to
  `/plan/`). The client expects raw plan bytes, not a redirect.
- **`GET /plan.sig`** returns **404 Not Found**. There is no file named
  `plan.sig` at the root; the file is `plan/plan.json.sig`.

### Digest format

The plan carries digests as `sha256:<hex>` (colon). Blob filenames and
URLs use `sha256-<hex>` (hyphen). The client converts the colon to a
hyphen before requesting.

---

## Web server configuration

Both configs below listen on **8080**, matching the `mirror.lan:8080`
endpoints used in the client examples. If you change one, change the
other -- a mismatch leaves every machine polling a closed port, and the
only symptom is that nothing ever converges. Running these in a
container adds a second place to get it right: publish the port
(`-p 8080:8080`) so the container's listener is reachable at the port
the clients were told to use.

### nginx

```
# nginx config for greentic airgap update mirror.
#
# Serves the --push-to directory layout produced by:
#   greentic-deployer op updates import --push-to <DIR>
#
# Directory layout on disk:
#   <DIR>/plan/plan.json       raw plan bytes
#   <DIR>/plan/plan.json.sig   DSSE envelope bytes
#   <DIR>/plan/meta            poll metadata
#   <DIR>/blobs/sha256-<hex>   content-addressed blobs
#   <DIR>/.push-lock           writer lock (must NOT be served)
#
# Client request mapping (plan_endpoint = http://host:port/plan):
#   GET /plan/meta  ->  <DIR>/plan/meta           (identity)
#   GET /plan       ->  <DIR>/plan/plan.json      (rewrite)
#   GET /plan.sig   ->  <DIR>/plan/plan.json.sig  (rewrite)
#   GET /blobs/sha256-<hex> -> <DIR>/blobs/sha256-<hex> (identity)

worker_processes 1;
error_log /var/log/nginx/error.log warn;
pid       /tmp/nginx.pid;

events {
    worker_connections 64;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    sendfile      on;

    server {
        # Must match the port in --plan-endpoint / --blob-base-url.
        listen 8080;
        server_name _;

        root /srv/mirror;

        # --- security: deny dotfiles everywhere ---
        location ~ /\. {
            return 404;
        }

        # --- security: disable directory listing globally ---
        autoindex off;

        # --- /plan (exact) -> plan/plan.json ---
        # Without this, nginx would try to serve the directory "plan/"
        # and return 301 to /plan/ (with trailing slash) or 403.
        location = /plan {
            alias /srv/mirror/plan/plan.json;
            default_type application/json;
            add_header Cache-Control "no-store, no-cache, must-revalidate" always;
        }

        # --- /plan.sig (exact) -> plan/plan.json.sig ---
        location = /plan.sig {
            alias /srv/mirror/plan/plan.json.sig;
            default_type application/octet-stream;
            add_header Cache-Control "no-store, no-cache, must-revalidate" always;
        }

        # --- /plan/meta (exact) -> plan/meta (identity) ---
        # This is the poll target the fleet hits every interval.
        # It MUST NOT be cached by intermediaries -- a stale meta
        # means a stale fleet.
        location = /plan/meta {
            alias /srv/mirror/plan/meta;
            default_type application/json;
            add_header Cache-Control "no-store, no-cache, must-revalidate" always;
            add_header Pragma "no-cache" always;
        }

        # --- /blobs/ -> content-addressed blobs (long-term cacheable) ---
        location /blobs/ {
            alias /srv/mirror/blobs/;
            default_type application/octet-stream;
            add_header Cache-Control "public, max-age=31536000, immutable" always;
            # Deny directory listing (redundant with global autoindex off,
            # but explicit)
            autoindex off;
        }

        # Everything else: 404
        location / {
            return 404;
        }
    }
}
```

### Caddy

```
# Caddy config for greentic airgap update mirror.
#
# Serves the --push-to directory layout produced by:
#   greentic-deployer op updates import --push-to <DIR>
#
# Client request mapping (plan_endpoint = http://host:port/plan):
#   GET /plan/meta  ->  <DIR>/plan/meta           (identity)
#   GET /plan       ->  <DIR>/plan/plan.json      (rewrite)
#   GET /plan.sig   ->  <DIR>/plan/plan.json.sig  (rewrite)
#   GET /blobs/sha256-<hex> -> <DIR>/blobs/sha256-<hex> (identity)

{
	admin off
}

:8080 {
	# --- security: deny dotfiles everywhere ---
	# Must be first: blocks .push-lock and any dotfile
	# before any other handler.
	@dotfiles path_regexp dotfile /\.
	respond @dotfiles 404

	# --- cache headers (set BEFORE rewrite, matching original
	#     request paths) ---

	# /plan/meta is the poll target -- must never be cached
	# by intermediaries.
	@plan_meta path /plan/meta
	header @plan_meta Cache-Control "no-store, no-cache, must-revalidate"
	header @plan_meta Pragma "no-cache"

	# /plan and /plan.sig change with each publish -- must not
	# be cached either.
	@plan_files path /plan /plan.sig
	header @plan_files Cache-Control "no-store, no-cache, must-revalidate"

	# /blobs/* are content-addressed -- cacheable forever.
	@blobs path /blobs/*
	header @blobs Cache-Control "public, max-age=31536000, immutable"

	# --- rewrites: map client URLs to on-disk filenames ---
	# /plan (exact) -> plan/plan.json
	# Without this, Caddy would try to serve the "plan" directory
	# and return 404.
	rewrite /plan /plan/plan.json
	# /plan.sig (exact) -> plan/plan.json.sig
	rewrite /plan.sig /plan/plan.json.sig

	# Serve files from the mirror directory.
	# browse is off by default -- no directory listing.
	root * /srv/mirror
	file_server
}
```

---

## Caching guidance

| Path | Cache-Control | Rationale |
|---|---|---|
| `/plan/meta` | `no-store` | Poll target (see below). |
| `/plan` | `no-store` | Changes every publish. |
| `/plan.sig` | `no-store` | Changes every publish. |
| `/blobs/sha256-<hex>` | `immutable` | Content-addressed. |

**Why `/plan/meta` must never be cached.** The fleet polls `/plan/meta`
and short-circuits when `meta.sequence` equals the last-applied
sequence. If an intermediary caches `meta`, the fleet stops seeing new
sequences and **silently stalls** -- no convergence until the cache
expires. There is no error, no retry, no log line -- machines simply
believe they are up to date.

Do **not** put a caching reverse proxy between the mirror and the fleet
unless it respects these `Cache-Control` headers. A proxy that caches
`/plan/meta` will silently stall the fleet.

---

## Client configuration

Point each environment at the mirror with `op updates config-set`:

```bash
greentic-deployer op updates config-set <ENV_ID> \
  --plan-endpoint http://mirror.lan:8080/plan \
  --blob-base-url http://mirror.lan:8080/blobs \
  --insecure-http true \
  --poll-interval-secs 300 \
  --on-notify stage \
  --push-enabled false \
  --enabled true
```

`--push-enabled false` is **strongly recommended** for a static mirror,
and is easy to miss because it defaults to `true`. It is not required
for correctness -- the poll loop is the fallback and converges on its
own -- but without it the runtime generates continuous failed
connection attempts that look exactly like a broken mirror. Push is
opt-*out*: an enabled channel
subscribes to a server-sent-event stream unless told not to. When
`--stream-endpoint` is unset the runtime derives one by stripping the
`/plan` suffix off the plan endpoint and appending `/updates/stream`, so
the example above would have the runtime open an SSE connection to
`http://mirror.lan:8080/updates/stream` -- a route a static file server
does not serve, and which the configs above answer with 404. Tier 2 is
poll-only; the live plan server that serves that stream is a separate,
deferred piece of work.

Verify with:

```bash
greentic-deployer op updates config-show <ENV_ID>
```

The `resolved` block in the output shows the effective values after
defaults are applied. For a Tier 2 mirror the one to check is
`resolved.push_enabled`, which must be `false`.

`resolved.stream_endpoint` will still show a derived
`.../updates/stream` URL even when push is disabled -- the derivation
only looks at the plan endpoint and does not consult `push_enabled`.
That value is inert: the runtime gates streaming on `push_enabled`
alone, so a populated `stream_endpoint` next to
`resolved.push_enabled: false` is expected and is not a
misconfiguration.

### Flag notes

- **`--plan-endpoint`** -- the base URL the client polls. The client
  appends `/meta`, requests the bare path, and appends `.sig`.
  No trailing slash.
- **`--blob-base-url`** -- the base URL for content-addressed blobs.
  The client appends `/sha256-<hex>`.
- **`--insecure-http true`** -- required for plain HTTP to non-loopback
  hosts. Without it, only `https://` and `http://localhost` are
  accepted.
- **`--poll-interval-secs`** -- how often to poll `/plan/meta`. Minimum
  60, default 3600 (1 hour). Set lower for faster convergence inside
  the gap.
- **`--on-notify`** -- what to do when a new plan is found. `stage`
  (default) stages it for later `apply`; `record-only` records without
  staging; `apply` opts the environment into converging on its own, with
  no operator step. `apply` is what makes an in-gap fleet self-converge,
  but the executor lives in the runtime: a `greentic-start` predating
  `on_update` reads the legacy `on_notify` mirror and stages instead of
  failing, so an old runtime silently degrades to `stage` rather than
  converging. Check the version floor below before relying on `apply`.
- **`--push-enabled false`** -- strongly recommended here; see above.
  Defaults to `true`, which a static mirror cannot satisfy.
- **`--enabled true`** -- enables the poll loop.

To clear a previously set blob mirror:

```bash
greentic-deployer op updates config-set <ENV_ID> \
  --clear-blob-base-url
```

`--clear-blob-base-url` and `--blob-base-url` cannot be used together.

---

## Security model

Transport between the mirror and the fleet is **plain HTTP**. The trust
anchor is **not** the transport layer -- it is the DSSE signature over
the plan plus the environment's `trust-root.json`.

### What the mirror cannot do

The mirror is a **cache, not an authority**. A hostile or broken mirror
**cannot** cause a machine to run unsigned or tampered content:

- **Plans** are DSSE-verified against the trust root before staging.
  Modified bytes fail signature verification.
- **Blobs** are digest-verified against the SHA-256 in the signed plan.
  Modified bytes fail the digest check.

A hostile mirror can only cause **denial of service**: serve stale
bytes, refuse connections, or return errors. The fleet stalls but never
runs tampered content.

### What plain HTTP leaks

An observer on the in-gap network can see:

- Which environments exist (from the URL paths).
- Which versions are rolling out (from plan sizes and timing).
- Binary archive sizes and download timing.

If this metadata is sensitive, terminate TLS at the mirror (use
`https://` in `--plan-endpoint` and `--blob-base-url`, omit
`--insecure-http`).

### Scope of `--insecure-http`

`--insecure-http true` relaxes URL validation for `--plan-endpoint`,
`--stream-endpoint`, and `--blob-base-url` only. It does **not** affect
OCI insecure-registry settings or enrollment `ca_url` validation. Scope
it to the in-gap network; do not set it on internet-facing
environments.

---

## Version floors

There are three distinct floors, and they are easy to conflate. Which
one applies depends on how far you want the fleet to get without an
operator at the keyboard.

| Capability | Minimum `greentic-start` |
|---|---|
| Poll the mirror and **stage** a plan | any poll-capable version |
| **Apply** content plans autonomously (`--on-notify apply`) | `v1.1.9` |
| **Binary** convergence from the mirror | the C4 publish (below) |

**Staging** works on any version that can poll. The plan is fetched,
verified and staged; an operator then applies it per machine.

**Autonomous content apply** requires `v1.1.9` or later, the first
release that understands `on_update`. An older runtime reads the legacy
`on_notify` mirror instead, which means it silently stages rather than
failing -- so a fleet configured with `--on-notify apply` but running
pre-`v1.1.9` binaries will sit waiting for a manual step with nothing in
the logs to say why. Verify the runtime version before relying on
`apply`.

**Binary convergence** (plans carrying binary blobs fetched from the
mirror) requires `greentic-start` at or above the C4 blob-mirror
publish:

| Identifier | Version |
|---|---|
| Library (binary-bifurcated) | `greentic-start 1.2.0-dev.30545101936` |
| Binary (`-dev` namespace) | `greentic-start-dev 1.2.30545101936` |
| Dev Publish run ID | `30545101936` |

Both versions are confirmed present on crates.io. A `greentic-start`
older than this will poll and stage content-only plans but **cannot
fetch blobs from the mirror** -- it lacks the `fetch_blob_from_mirror`
code path entirely.

---

## Trailing-slash footgun

`plan_endpoint` must **not** end with a trailing slash. The client
strips trailing slashes via `trim_end_matches('/')`, so this only
matters if the endpoint is misconfigured before the client normalizes
it. If the web server receives requests with a trailing slash (e.g.
from a misconfigured intermediate proxy), two of three plan requests
fail:

| Request | nginx | caddy |
|---|---|---|
| `GET /plan/` | 404 | 404 |
| `GET /plan//meta` | 200 | 200 |
| `GET /plan/.sig` | 404 | 404 |

`/plan/.sig` is blocked by the dotfile rule (nginx) or simply not found
(caddy). Only `/plan//meta` survives via path normalization.

---

## Troubleshooting

### 404 on `GET /plan`

The rewrite is missing. Without it, `/plan` resolves to the `plan/`
directory on disk. nginx returns 301 (redirect to `/plan/`); caddy
returns 404. Verify the rewrite is present in your server config (see
the nginx and Caddy configs above).

### 403 on `GET /blobs/`

nginx returns 403 when directory listing is disabled (`autoindex off`)
and a request targets a directory. This is correct -- the blobs
endpoint serves individual files at `/blobs/sha256-<hex>`, not a
directory listing.

### Repeated SSE / stream connection errors against the mirror

The channel is trying to open a pushed-update stream the static mirror
does not serve. `push_enabled` is opt-*out* and defaults to `true`, and
an unset `--stream-endpoint` is derived from the plan endpoint by
stripping `/plan` and appending `/updates/stream`. Fix: set
`--push-enabled false`. Convergence still happens -- the poll loop is
the fallback and is all Tier 2 needs -- so this is noise rather than a
stall, but it looks like a broken mirror.

### Fleet stalls at a stale sequence

`/plan/meta` is being cached by an intermediary (proxy, CDN, or
in-kernel cache). The fleet polls `/plan/meta` and short-circuits when
`sequence` matches the last-applied value. A cached `meta` means no
machine sees the new sequence. Fix: ensure `Cache-Control: no-store` is
set on `/plan/meta` and that no intermediary ignores it.

### Digest mismatch on blob fetch

The blob on the mirror does not match the SHA-256 in the signed plan.
Possible causes:

- A corrupt blob already on the mirror. **Re-running the import does
  not repair it.** The writer skips any blob path that already exists
  as a regular file, on filename alone -- it never compares contents,
  and its own comment records that a corrupted pre-existing file is
  caught by readers rather than by the writer. Recovery: delete the
  specific `blobs/sha256-<hex>` file named in the error, then re-run
  the same `op updates import --push-to` command, which will write it
  fresh. (Blobs are written via temp-file plus atomic rename, so an
  interrupted import leaves the blob absent, not truncated -- a
  mismatch points at corruption after the fact, e.g. filesystem damage
  or an edit in place.)
- A proxy applied transparent compression (`Content-Encoding: gzip`).
  The `greentic-start` client uses `reqwest` with only the `blocking`
  and `rustls` features -- no `gzip` or `deflate` feature -- so it
  does **not** transparently decompress. A proxy that force-compresses
  responses will cause every blob digest to fail. Disable forced
  compression on the mirror.

### `.push-lock` is served as a downloadable file

The dotfile-blocking rule is missing from the server config. Add the
`location ~ /\. { return 404; }` block (nginx) or the `@dotfiles`
matcher (Caddy) from the configs above.

### Import refuses with "refusing downgrade to sequence N"

The `--push-to` directory already serves a higher sequence. The import
itself committed successfully (receipt written), but the mirror write
was refused. This is correct -- the monotonic guard prevents serving an
older plan. Publish a new plan with a higher sequence number.

### Import refuses with "same sequence with a different plan"

The directory already serves the same sequence number but with a
different `plan_sha256`. Two different plans must not share a sequence
number -- bump the sequence to publish the new plan.
