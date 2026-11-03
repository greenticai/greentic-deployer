# ssh-host deployer — internals

`greentic.deployer.ssh-host@^0.1.0`, in `src/env_packs/ssh_host/`. It deploys
greentic-start to a plain Linux VM with systemd over SSH. Opt-in per env: bind it
with `op env-packs add <env> --slot deployer --kind greentic.deployer.ssh-host@0.1.0`;
it is not a `local` default.

> **Status: wired into the CLI, verified on one real VM.** The `Deployer` verbs,
> the credentials probes, the wizard and the registry entry are tested against a
> simulated VM, and `tests/ssh_host_live.rs` ran them (library and CLI) against a
> real Ubuntu 24.04 VM. See "Using it from the CLI" for the operator flow and
> "Verified on a real VM" for what was and was not proved.

## Using it from the CLI

The wiring is `src/cli/ssh_host.rs`; every path uses the same strict answers
parser as the deployer (`params.rs`), so a bad answer is refused where it is written.

1. **Bind** the deployer with its answers (host, user, port, identity_file,
   known_hosts_file, install_dir, service_name, start_binary, listen_port, expose,
   use_sudo, service_user — see `wizard.qaspec.yaml`). Either:
   * `op --answers payload.json env-packs add|update` with
     `{"environment_id","slot":"deployer","kind":"greentic.deployer.ssh-host@0.1.0","pack_ref","answers_ref":"env-packs/deployer/answers.json"}`
     (`answers_ref` is relative to the env dir; the file is validated when the binding
     is written), or
   * `op --answers manifest.json env apply|up` with a `packs[]` entry carrying
     `answers` inline or `answers_ref` (validated at plan time, before anything changes).
2. `op credentials requirements` binds the answers' SSH target to the handler's
   credentials, so the six probes really run. A binding with no answers still fails
   closed (every capability `Fail`, "records no answers").
3. **Deploy** with `op --answers manifest.json env up --yes --non-interactive`
   (a minimal manifest `{"schema":"greentic.env-manifest.v1","environment":{"id":"<env>"}}`
   is enough for an env that already has the binding) or, for one revision,
   `op env apply-revision <env> <revision>`.

Why `env up`: it is the repo's "bring this environment up" verb and already
dispatches per deployer kind after the deployer-agnostic apply (Cloud Run does the
same in `cloudrun_env_up`). `apply-revision` is the granular verb the other
imperative backends (AWS, Cloud Run) already have, so it dispatches too. ssh-host
needs neither the `k8s-client` nor the `deploy-gcp-cloudrun` feature, and `env up`
skips that feature gate for it.

`env up` warms ONCE for every revision the VM serves (`cloudrun_revisions_to_warm`:
the revisions a traffic split names, or the newest of a split-less deployment) because
the VM runs one service over one store; `apply-revision` warms the same set plus the
named revision, so the two verbs produce the same store and are idempotent with each
other. It fails with a pointer to `op deploy` when the env has no such revision.

`env up` prints one JSON envelope on stdout:
`{"op":"up","noun":"env","result":{environment_id, kind, host, service, install_dir,
listen_addr, store_slot ("store-a"|"store-b"|null), changed (bool: false = the VM was
already converged, nothing uploaded or restarted), exposed, revisions[], endpoint_url
(only when exposed)}}`. Errors are the standard stderr envelope, exit code non-zero.
The SSH identity is never in any output. `--dry-run` stops after the plan and never
reaches the VM. `apply-revision` reports `identity` as `ssh-identity-file` or
`ssh-default` (how ssh authenticates, never with what) and `worker_name` = the unit.

Dev-store: shipped (filtered by `read_dev_secrets_bytes`) only when a `Secrets`-slot
pack is bound and it is the dev-store backend, the same rule as Cloud Run; a
Vault-backed env ships none.

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
`expose=true`; a loopback bind returns `None` (see "Listen address"). The CLI calls
`SshHostDeployerHandler::warm_with_report(env, revision_ids, answers)`, the same
procedure for several revisions that also reports service, listen address, whether
anything changed and the live store slot (one extra `readlink`; `warm_revision`
stays exactly as before).

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
| `credentials.rs` | `impl DeployerCredentials`: six VM probes (seven with a tunnel) |
| `tunnel/` | the `tunnel` answer: `TunnelProvider`, registry, gate, guard, providers |
| `fake.rs` (test) | `FakeRemote`, a simulated VM |
| `tests.rs` (test) | handler, conformance, warm/drain scenarios |
| `tests_tunnel.rs` (test) | the `tunnel` answer against the simulated VM |

## Tunnels

A VM that is not directly reachable (a customer network, a bastion, a VPN) is
reached through the optional `tunnel` answer. No `tunnel` (or `none`) changes
nothing: `ssh` gets exactly the arguments it always did (golden test
`no_tunnel_leaves_the_ssh_argv_byte_identical`).

```json
{"host": "10.20.0.5", "user": "greentic",
 "tunnel": {"kind": "openconnect", "settings": {
   "server": "vpn.customer.example", "servercert": "pin-sha256:...",
   "user": "svc-greentic", "password_file": "/run/secrets/vpn-pw",
   "totp_seed_file": "/run/secrets/vpn-seed"}}}
```

`tunnel` is an object, and the wizard (`wizard.qaspec.yaml`) has only flat string
questions, so it is **not asked by the wizard**: it goes in the answers JSON
(`answers_ref` / `answers`) alone. `params::WIZARD_EXCLUDED_KEYS` records that and
a test keeps the wizard and the parser in step. The answer has exactly two fields
(`kind`, `settings`, the shape of the contract type `VmTunnel`); settings are
strings, and a number or boolean is read as its text. The kind and every setting
are validated when the answers are written, with an allow-list per value (no
whitespace, `;`, `$(`, backtick, quotes, `..`, newline, leading `-`); errors name
the key and never echo the value.

### One mechanism

A hosted deployer has no `NET_ADMIN` and no `/dev/net/tun`, so every kind works in
userspace and ends as `ssh -o ProxyCommand=...`. The command rides on
`RemoteTarget::proxy_command`, so commands, `tar` streams and uploads all take the
same route and the `Remote` trait did not change.

| kind | what runs | status |
|---|---|---|
| `none` | nothing | done |
| `jump` | a second `ssh -W %h:%p` to the bastion; the bastion has its OWN `jump_known_hosts_file` (required) and `StrictHostKeyChecking=yes` | done; argv-tested only |
| `proxy` | the gate dials the customer's SOCKS5 / HTTP CONNECT proxy | done; tested against fakes on loopback |
| `openconnect` | `openconnect --script-tun --script "ocproxy -D <port>"`, then the gate | done for `anyconnect`; tested with a stub only |
| `wireguard`, `tailscale` | would be `wireproxy` / `tailscaled --tun=userspace-networking` | recognised, `up()` answers "not available in this build" |
| `openvpn`, `ikev2`, `zerotier` | need a kernel interface | recognised, `up()` answers "needs a runner, not available yet" |

Helper kinds and `proxy` do not give `ssh` the helper's port. The **destination
gate** (`tunnel/gate.rs`) listens on its own loopback port and forwards only
`target_host:target_port`; the `ProxyCommand` is `nc -X 5 -x 127.0.0.1:<gate> %h %p`.
Any other CONNECT is refused before anything is dialled, so a helper that can reach
a whole network (ocproxy, tailscaled) is not a general proxy for whatever else shares
the container. Residual: another process in the container can still ask the gate
for the VM (all it can get) and can reach the helper's raw loopback port; separating
tenants is the container's job. The registry also refuses a loopback, link-local
(metadata) or unspecified target, and `proxy` / `jump` / `openconnect` refuse such
an address as their own server.

### The provider contract (`TunnelProvider`)

```rust
pub trait TunnelProvider: fmt::Debug + Send + Sync {
    fn kind(&self) -> &'static str;
    fn validate(&self, settings: &BTreeMap<String, String>) -> Result<(), TunnelError>;
    fn up(&self, ctx: &TunnelContext<'_>) -> Result<TunnelUp, TunnelError>;
}
pub struct TunnelContext<'a> {
    pub settings: &'a BTreeMap<String, String>,
    pub login_user: &'a str,
    pub target_host: &'a str,
    pub target_port: u16,
    pub ready_timeout: Duration,          // DEFAULT_READY_TIMEOUT = 60 s
}
pub struct TunnelUp {
    pub proxy_command: Option<String>,    // None = connect directly
    pub guard: TunnelGuard,
}
```

Register a new provider in `TunnelRegistry::builtin()`. What `up` must do:

* **Once per `env up`.** `Session::open` brings the tunnel up when a warm or drain
  starts and drops it when the session ends; the credentials probe does the same for
  all its probes. A provider is never called per command.
* **Prove it, don't assume it.** Return only after `gate::publish` has made a SOCKS5
  CONNECT through the gate to the VM and read an `SSH-` banner back. A listener that
  accepts is not proof: wireproxy, tailscaled and ocproxy all accept before the
  tunnel carries traffic. Give up after `ctx.ready_timeout`.
* **Never retry a failed authentication.** Gateways lock accounts. (Two commands
  that each log in, e.g. `op credentials requirements` and then `op env up`, are two
  logins; that is the operator's call.)
* **A free port, never a fixed one:** `support::free_loopback_port()`.
* **Secrets:** read from `0600` files (`support::read_secret_file`, which refuses a
  file others can read), keep them in `Zeroizing` memory, hand them to a helper on
  its stdin or through `ScratchDir::write_secret` (`0600` in a `0700` directory).
  Never argv, never the environment, never an error. A helper's output goes to a
  scratch file and is **classified into a fixed sentence**, not quoted: it can echo
  user names and form fields.
* **Cleanup is the guard's job.** Put every child (`adopt_child`, or
  `adopt_group_leader` for one spawned with `process_group(0)`, which signals the
  whole group), hook (`on_drop`) and scratch dir (`adopt_scratch`) in
  `TunnelUp::guard`. Dropping it kills and reaps the children, runs the hooks in
  reverse, and deletes the directories. On any `Err` the guard you built is dropped.
* **Validate first.** `validate` runs when answers are parsed and must start
  nothing and read no file.

### `openconnect`

Cisco AnyConnect first (`protocol` accepts only `anyconnect`; the other protocols
`openconnect` speaks are the same code path and are left out until someone can test
them). Automated: user + password, and password + a TOTP code **computed here** from
the customer's seed (`totp.rs`: RFC 6238, HMAC-SHA1, 6 digits, 30 s; checked against
the RFC vectors). Not automatable: SAML / SSO, push or approval MFA (Duo, Okta
Verify), HostScan / Cisco Secure Desktop posture; the error says so and points at a
service account exempt from those, or a runner inside the customer's network.

* The password and the code go on `openconnect`'s stdin (`--passwd-on-stdin`):
  `second_prompt` (default) sends the code as the answer to the gateway's second
  prompt, `append` sends `password+code` as one line. Which one a given gateway
  wants is not known without trying it.
* `servercert` (`pin-sha256:...`) is **mandatory** (it also turns system trust off).
* **One attempt.** A refused login is reported once and not retried.
* The host clock is refused when it is plainly wrong (before 2025 or after 2100), and
  a code is never computed in the last 3 seconds of its step. Skew of a few seconds
  or minutes cannot be detected offline; the gateway will refuse the code.
* `--no-dtls`: everything over TLS on 443. The tunnel is single-use per deploy:
  `openconnect`'s reconnect is not relied on.

### Packages the image needs (not installed by this change)

`openssh-client`, `netcat-openbsd` (the OpenBSD `nc`, for `-X`), `openconnect` and
`ocproxy` (Debian trixie: 9.12 / 1.60). The deployer image is not touched here.
Later: `wireproxy` and `tailscale` would go in through `Dockerfile.tools`.

### Verification

Unit tests only, no network: registry, settings (injection tables), argv goldens,
guard cleanup (including a grandchild), the gate against a fake SOCKS5 server, the
`proxy` kind against fake SOCKS5 / HTTP CONNECT servers on loopback, the
`openconnect` kind against a stub shell script that records its argv and stdin and
a fake SOCKS5 listener playing `ocproxy`, and the handler / credentials against
`FakeRemote`. **`jump` has only been tested through its argv and the `FakeRemote`;
it has not been run against a real bastion, and no test uses a shared VM.**

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

## Follow-ups

1. **A `Vm` deploy target in the contract** (`DeployTarget::Vm`, designer/admin).
2. **A readiness wait on `/healthz`.** The deployer checks `is-active` after a 3 s
   settle, not the HTTP endpoint (the live tests poll `/healthz` themselves).
3. **No rollback on a failed start.** A store/unit change whose service then fails
   to stay active leaves the new generation active and the service restarting
   (`Restart=on-failure`); the previous store is still in the other slot. A
   rejected *binary* is the exception (it is never swapped in).
4. **Resumable uploads.** The 164 MB binary upload restarts from zero if the
   connection stalls (ServerAlive: 3x15 s); one run lost a 15 MB partial upload
   that way on a slow link.
5. `op env drain-revision` / `op bundles retire` for ssh-host go through the
   generic paths (the adapter claims no `drain`/`remove` capability); `env up` is
   the only verb that adds a revision to the VM.

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

### The CLI live test

`ssh_host_through_the_cli` (same file, same variables) drives the real binary:
`env-packs update` (bind), `credentials requirements` (all six probes must pass),
`env up`, `env up` again (must report `changed: false`, same start stamp, same
install-dir fingerprint), `/healthz` and the UI path 200, then the same cleanup. Run
one test by name: `cargo test --test ssh_host_live ssh_host_through_the_cli -- --ignored --nocapture`.
Its store is an `op env init` + `op deploy` store (the CLI test rebinds the deployer
to ssh-host in a copy). Run once against Ubuntu 24.04 with a root login and
`service_user=nobody`: passed, and the VM was left empty afterwards.

`tests/ssh_host_cli.rs` (not ignored) runs the binary against a stub `ssh` on
`PATH`: it proves the answers reach the ssh command line, bad input is refused
before anything is contacted, and the identity path never appears in output.

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
  live runs (library and CLI) logged in as root.
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
* Network flakiness on large uploads (see "Follow-ups" 4).
* TLS and DNS are not handled.
* Every `tunnel` kind against the real thing: `jump` against a real bastion,
  `proxy` against a real customer proxy, `openconnect` against a real gateway (and
  whether `second_prompt` or `append` is what a given Cisco policy wants), and
  `ssh` honouring the generated `ProxyCommand` with a real `nc -X`.
