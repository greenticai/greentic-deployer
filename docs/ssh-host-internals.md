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
   `greentic-start.new`, `chmod 0755`, `mv -f` over the live name. Without it,
   `test -x` the installed binary and fail with a pointer to `start_binary`.
3. **Store.** Build a deterministic snapshot of the local `<store_root>/<env_id>/`
   (see below), skip it if `<install_dir>/store/.greentic-store.sha256` already
   holds its content hash, otherwise **stream** it over ssh into
   `tar -xf - -C <inactive slot>` (`store-a` / `store-b`), carry the runtime's
   `revision-signing.key` over from the active slot, link `<slot>/logs` to
   `<install_dir>/logs`, and activate with `ln -sfn` + `mv -T` (a single
   `rename(2)` of the `store` symlink).
4. **Unit.** Render, upload, `cmp -s` against `/etc/systemd/system/<svc>.service`;
   `sudo -n install` + `daemon-reload` only if it differs.
5. `enable` + `restart` if 2, 3 or 4 changed anything, else `enable --now`; then
   `systemctl is-active` must say `active`.

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
`revision-signing.key` / `logs/` at the store root, are never read. A symlink in
the tree is refused. Limit 256 MiB.

The dev-store bytes MUST come from `cli::env::read_dev_secrets_bytes` (it strips
the deployer's own bound credential). `snapshot.rs` never reads a
`.dev.secrets.env` from disk, so it cannot bypass that filter. The dev-store
master key is not bound to a host, so the snapshot is secret to anyone who holds
it: it goes only over ssh, from a 0600 local temp file, into `tar` on the VM —
no archive is ever written to the VM's disk — and extracted modes are 0600/0700.
No SSH credential is ever put in the store.

## Runtime state survives a store change

greentic-start writes `revision-signing.key` and `logs/` inside the store root. A
changed snapshot goes to a *fresh* slot, so without care that state would be
lost. Instead: the key is `cp -p`'d from the active slot into the new one before
activation, and `<slot>/logs` is a symlink to `<install_dir>/logs`, outside any
slot. There is no `rsync --delete` anywhere. A store change still orphans
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
it in the snapshot keeps the operator's local store untouched.) Which of
`runtime.json` and the environment variables wins in the runtime is unverified.

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
3. **A readiness wait.** `is-active` is checked once; there is no `/healthz`
   poll from the operator machine.

## Not verified

Everything here ran against `FakeRemote`, which implements the command
vocabulary with the semantics it was given. Unverified against reality:

* **Linux, sshd, systemd.** The spike proved the store layout and the exclusion
  set macOS-arm64 path-to-path only. `SystemSsh` has been exercised for its
  argument construction and quoting, never against a running `sshd`. The unit has
  never been loaded by systemd.
* GNU coreutils behaviour assumed on the VM: `mv -T`, `ln -sfn`, `cmp -s`,
  `cp -p`, `install -o root -g root`, `sha256sum`, `tar -xf -`.
* The glibc floor (2.39) is the coordinator's reading of the release build host.
* Whether `runtime.json` or the environment variables decide the bind address,
  and that `.greentic-store.sha256` at the store root is tolerated by the runtime.
* The `.greentic/state/dev/.dev.secrets.env` exclusion is this deployer's
  fail-safe addition, not part of the proven set.
* `bundle_source_uri` is not touched: the VM's greentic-start must be able to
  fetch every revision's bundle itself (`revisions/*/bundle.gtbundle` is not
  shipped, and a `file://` source on the operator's machine will not resolve).
* TLS and DNS are not handled.
