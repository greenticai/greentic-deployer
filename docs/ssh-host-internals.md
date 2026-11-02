# ssh-host deployer — internals

`greentic.deployer.ssh-host@^0.1.0`, in `src/env_packs/ssh_host/`. It deploys
greentic-start to a plain Linux VM with systemd over SSH. Opt-in per env: bind it
with `op env-packs add <env> --slot deployer --kind greentic.deployer.ssh-host@0.1.0`;
it is not a `local` default.

> **Status: draft, not wired into the CLI.** The `Deployer` verbs, the
> credentials probes, the wizard and the registry entry exist and are tested
> against a simulated VM. `op env apply-revision` / `op credentials requirements`
> do not yet dispatch to it — see "Not wired" below. Nothing here has run against
> a real `sshd`, a real systemd or a Linux host. The store layout was proven
> path-to-path on macOS arm64 only.

## The shape of a deploy

greentic-start does not run one bundle file; it reads the env store:
`greentic-start start --store-root <dir> --env <env_id> --no-browser --nats off
--no-updates`. So deploying to a VM is "synchronize the store, then (re)start a
service", and `warm_revision` does:

1. `mkdir -p <install_dir>/{bin,home,logs}`. `home` is the service's writable
   `HOME` (greentic-start creates `$HOME/.greentic/environments`); `logs`
   outlives store changes.
2. **Binary.** With `start_binary` set, compare its SHA-256 to
   `sha256sum <install_dir>/bin/greentic-start`; if different, upload
   `greentic-start.new`, `chmod 0755`, **run `greentic-start.new --version`** (it
   must exit 0 AND print something — the remote shell runs an empty file as an empty
   script, exit 0, no output), then `mv -f` over the live name; a rejected file is
   removed and the installed binary is untouched. Without it,
   `test -x` the installed binary and fail with a pointer to `start_binary`.
3. **Store.** Build a deterministic snapshot of the local `<store_root>/<env_id>/`
   (see below), skip it if `<install_dir>/store/.greentic-store.sha256` already
   holds its content hash, otherwise **stream** it over ssh into
   `tar -xf - -C <inactive slot>` (`store-a` / `store-b`), carry the runtime's
   `<env_id>/revision-signing.key` over from the active slot, link
   `<slot>/<env_id>/logs` to `<install_dir>/logs`, hand the slot to `service_user`
   (when set), and activate with `ln -sfn` + `mv -T` (a single `rename(2)` of the
   `store` symlink).
4. **Unit.** Render, upload, `cmp -s` against `/etc/systemd/system/<svc>.service`;
   `sudo -n install` + `daemon-reload` only if it differs.
5. `enable` + `restart` if 2, 3 or 4 changed anything, else `enable --now`; wait
   3 s (a process that dies at startup is `activating (auto-restart)`, and an
   immediate check can read `active` for it), then `systemctl is-active` must say
   `active`. On failure the error quotes the last 12 journal lines.

With `service_user` set (and different from the login user) the account is looked
up first (`id -u`, before anything changes), `home/`, `logs/` and the store are
`chown -R -h`'d to it, and the unit gets `User=`. Use it to log in as root and run
as an unprivileged account.

`WarmOutcome.endpoint_url` is `http://<host>:<listen_port>` only when
`expose=true`; a loopback bind returns `None` (see "Listen address").

`drain_revision` stops the service only when the env routes **no** traffic at
all (one service serves every routed revision, so stopping it for one drained
revision would cut the others). `archive_revision` and `apply_traffic_split`
touch nothing on the VM. `capabilities()` is `NONE`.

## The store snapshot (`snapshot.rs`)

The walk of `<store_root>/<env_id>/` minus these SPECIFIC exclusions (exact names
and positions, relative to the env dir):

| path | treatment |
|---|---|
| `backups/`, `audit/` | skipped |
| `revision-signing.key`, `logs/` | skipped (runtime-written; the VM keeps its own) |
| files named exactly `.lock` or `.dev.secrets.env.lock` | skipped |
| `revisions/*/bundle.gtbundle` | skipped |
| `.greentic/dev/.dev.secrets.env` | **replaced** by the injected, filtered bytes (omitted if none) |
| `.greentic/state/dev/.dev.secrets.env` | skipped (the runtime's other dev-store candidate; an unfiltered copy) |
| `environment.json` | **replaced** by `seed_environment_bytes` (the Cloud Run seed function) |
| `runtime.json` | `listen_addr` rewritten to `<bind>:<listen_port>` |

**Never a glob.** `*.lock` would also drop `pack-list.lock`, giving a VM that
answers `/healthz` 200 while webchat fails with "deployment ... not known to
dispatcher". `pack-list.lock`, `bundle.lock.json`, `bundle-lock.json` ship (a
test pins it). A `bundle/.greentic/dev/.dev.secrets.env` inside a revision
belongs to the bundle and ships as-is. Other envs, and the runtime's own
store-root state, are never read. A symlink in
the tree is refused. Limit 256 MiB.

The dev-store bytes MUST come from `cli::env::read_dev_secrets_bytes` (it strips
the deployer's own bound credential). `snapshot.rs` never reads a
`.dev.secrets.env` from disk, so it cannot bypass that filter. The dev-store
master key is not bound to a host, so the snapshot is secret to anyone who holds
it: it goes only over ssh, from a 0600 local temp file, into `tar` on the VM —
no archive is ever written to the VM's disk — and extracted modes are 0600/0700.
No SSH credential is ever put in the store.

## Runtime state survives a store change

greentic-start writes `revision-signing.key` and `logs/` inside the ENV
directory, `<slot>/<env_id>/` (measured on a real VM — the first implementation
looked at the slot root, so every store change silently generated a new key and
the persistent `logs/` stayed empty). A changed snapshot goes to a *fresh* slot,
so without care that state would be lost. Instead: the key is `cp -p`'d from the
active slot into the new one before activation, and `<slot>/<env_id>/logs` is a
symlink to `<install_dir>/logs`, outside any slot. There is no `rsync --delete` anywhere. A store change still orphans
anything *else* the runtime wrote into the old slot (it stays there, in the
previous generation).

## Listen address (decision)

The proven store's `runtime.json` has `listen_addr 127.0.0.1:8080`. Decision:
**loopback by default**, because exposing plain HTTP on every interface should be
a deliberate act. The answer `expose=true` binds `0.0.0.0`. Either way the bind
address and `listen_port` are applied in BOTH places — the shipped `runtime.json`
and `GREENTIC_GATEWAY_LISTEN_ADDR` / `GREENTIC_GATEWAY_PORT` in the unit — so
whichever the runtime honours agrees. A loopback deploy needs a reverse proxy
(nginx, Caddy) for TLS and public access; the deployer does not set one up.
(`op config set --listen-addr` would change the local store instead; rewriting
it in the snapshot keeps the operator's local store untouched.) Both were
applied in the live run and the service listened on exactly `127.0.0.1:<listen_port>`;
which of the two wins when they disagree was not isolated.

## Module map

| file | role |
|---|---|
| `params.rs` | strict answer parsing; the safe-charset rules |
| `remote.rs` | `Remote` trait (`run`, `run_with_stdin`, `upload`), `SystemSsh` |
| `snapshot.rs` | the filtered store archive |
| `render.rs` | pure: the systemd unit |
| `steps.rs` | the warm/drain procedure on top of `Remote` |
| `deployer.rs` | `impl Deployer` (passes `run_conformance`) |
| `credentials.rs` | `impl DeployerCredentials`: six VM probes |
| `fake.rs` (test) | `FakeRemote`, a simulated VM |
| `tests.rs` (test) | handler, conformance, warm/drain scenarios |

## Invariants — do not regress

* **No local shell, no unvalidated interpolation.** `SystemSsh` spawns `ssh` with
  an argument array. The remote command is built by quoting each argv element
  (`remote::shell_quote`); inputs that reach it (`install_dir`, `service_name`, the
  env id) are additionally restricted to `[A-Za-z0-9._/-]`, absolute, no `..`.
  Host and user are checked for a leading `-` so they cannot become ssh options.
  Output of `readlink` on the VM is only ever compared against our two slot
  paths, never interpolated.
* **Host keys are always verified**, nothing ever prompts (`BatchMode=yes`,
  `StrictHostKeyChecking=yes`). There is deliberately no answer to turn this off.
* **`identity_file` is a path, never read into the store, and never printed**:
  `Debug` redacts it, parse errors do not echo it, `SystemSsh` scrubs it from
  ssh's stderr.
* **The live store is switched only by the last action of its step**, so a
  failed step leaves the previous complete store active; the previous generation
  stays in the other slot (manual rollback: repoint the symlink).
* **Fail closed.** No answers and no injected fallback is an error; no bound
  local store is an error; the default credentials report every capability as
  `Fail` (never `Skipped`).
* **Every verb is idempotent**; a converged VM gets no restart, no extract, no
  unit install (pinned in `tests.rs`).

## Decisions worth knowing

* `requires_credentials_material() == false`: the only secret is the operator's
  SSH key, referenced by path and never stored, so there is nothing to bootstrap,
  rotate or strip from a seed (the `local-process` shape, not K8s/AWS).
  `bootstrap` is `NotApplicable`.
* Upload is `ssh host 'umask 077 && cat > path' < file`, not `scp`: one binary,
  no legacy-scp filename handling, no dependency on the VM's sftp subsystem.
* Sudo is used only for `install` into `/etc/systemd/system` and `systemctl`.
  The install dir is expected to be owned by the login user, and the service runs
  as that user (no `User=` line for root). A dedicated non-root user is advised.
* Capabilities beyond the four in the original brief: `ssh-host.glibc` (release
  binaries need glibc >= 2.39 — Ubuntu 24.04 / Debian 13; Debian 12 and Ubuntu
  22.04 will not run them; checked with `getconf GNU_LIBC_VERSION`, falling back
  to `ldd --version`, musl rejected) and `ssh-host.privilege` (`sudo -n true`, or
  uid 0 when `use_sudo=false`).
* `--no-updates` stops greentic-start from replacing the binary on the VM behind
  the deployer's back.

## Not wired (follow-ups)

1. **CLI dispatch.** `cli::env::apply_revision` only dispatches K8s / AWS-ECS /
   Cloud Run, and `op credentials requirements` resolves the handler's own
   default credentials, which hold no target — so on a real env today the probes
   fail closed with "no SSH target is bound". The seams exist:
   `SshHostCredentials::with_target`, `SshHostDeployerHandler::with_remote`,
   `with_local_store(store_root, dev_secrets)`. Missing: the CLI reading the
   binding's answers, building the handler, passing `store.root()` and
   `read_dev_secrets_bytes`.
2. **A `Vm` deploy target in the contract** (`DeployTarget::Vm`, designer/admin).
3. **A readiness wait on `/healthz`.** The deployer checks `is-active` after a 3 s
   settle, not the HTTP endpoint (the live test polls `/healthz` itself).
4. **No rollback on a failed start.** A store/unit change whose service then fails
   to stay active leaves the new generation active and the service restarting
   (`Restart=on-failure`); the previous store is still in the other slot. A
   rejected *binary* is the exception (it is never swapped in).
5. **Resumable uploads.** The 164 MB binary upload restarts from zero if the
   connection stalls (ServerAlive: 3x15 s); one run lost a 15 MB partial upload
   that way on a slow link.

## Verified on a real VM, and what is not

`tests/ssh_host_live.rs` (`#[ignore]`d, see below) was run against Ubuntu 24.04
(glibc 2.39, systemd 255, GNU coreutils 9.4) over a real `sshd` with a real
greentic-start `v1.2.40985621765`. It proved: the six credential probes; first
install (upload of the binary, snapshot stream, slot swap, unit install, start,
`/healthz` 200 and the demo bundle's webchat page 200); an unchanged warm is a
no-op (same start time, same install dir); a small store change flips the slot,
restarts and keeps the signing key; a binary that does not run is refused with the
old one still serving; drain stops the service only when no traffic is routed;
archive touches nothing. GNU `mv -T`, `ln -sfn`, `cmp -s`, `cp -p`, `install`,
`sha256sum` and `tar -xf -` behaved as assumed, the runtime accepted
`.greentic-store.sha256` at the slot root, glibc 2.39 is sufficient for this
release (a lower floor was not tested), and plain ssh uploads work.

Wrong assumptions the run corrected (each fixed in its own commit): the runtime's
state lives under `<slot>/<env_id>/`, not the slot root; an empty binary passes a
bare `--version` exit-code probe; a single `is-active` right after `restart`
cannot see a startup crash; and on a busy box root can be out of inotify
instances (128 per uid), so the service has to run as another account
(`service_user`) — greentic-start dies at boot with "Too many open files" otherwise.

### Running the live test

```text
GREENTIC_SSH_LIVE_HOST=...        GREENTIC_SSH_LIVE_USER=root
GREENTIC_SSH_LIVE_KNOWN_HOSTS=/path/to/known_hosts   # already trusts the VM
GREENTIC_SSH_LIVE_START_BINARY=/path/to/greentic-start-for-the-vm
GREENTIC_SSH_LIVE_STORE=/path/to/store-root          # holds <env_id>/, copied not modified
GREENTIC_SSH_LIVE_INSTALL_DIR=/opt/greentic-vmtest   # must contain "vmtest"
GREENTIC_SSH_LIVE_SERVICE=greentic-vmtest            # must start with that
GREENTIC_SSH_LIVE_LISTEN_PORT=18647                  # loopback, must be free
# optional: _PORT, _IDENTITY, _UI_PATH (a path that must answer 200), _SERVICE_USER, _KEEP=1
cargo test --test ssh_host_live -- --ignored --nocapture
```

There are no defaults, so nothing about a machine is ever committed. The test
prints "WILL CHANGE ON THE VM" before each mutating step and removes the unit and
the install dir at the end, also on failure (`_KEEP=1` skips that, to inspect a
failure or avoid re-uploading the binary; remove them yourself afterwards). It
only touches the install dir and the one unit, and refuses names that do not
contain `vmtest`. Note a first install uploads the whole binary (~160 MB).

## Not verified

* A non-root login (`sudo -n` paths, a non-root `User=`) against a real VM; the
  live run logged in as root.
* `systemd` versions other than 255, distros other than Ubuntu 24.04.
* `bundle_source_uri` is not touched: the VM's greentic-start must be able to
  fetch every revision's bundle itself (`revisions/*/bundle.gtbundle` is not
  shipped, and a `file://` source on the operator's machine will not resolve). The
  demo bundle in the live run was already inside the shipped `revisions/*/bundle/`.
* The `.greentic/state/dev/.dev.secrets.env` exclusion is this deployer's
  fail-safe addition, not part of the proven set; the live run shipped no
  dev-store at all (`dev_secrets = None`).
* Which of `runtime.json` and the unit's environment variables decides the bind
  address when they disagree.
* Network flakiness on large uploads (see "Not wired" 5).
* TLS and DNS are not handled.
