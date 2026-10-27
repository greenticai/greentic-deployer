# AWS ECS Fargate: seed and bundle delivery (decision record)

Status: decided 2026-10-27. Spike for the ECS Fargate parity effort
(`src/env_packs/aws` reaching parity with `src/env_packs/gcp_cloudrun`). No
production code ships with this document.

## External prerequisite (read first)

**A worker on Fargate cannot pull a bundle from a private Amazon ECR repository
with the greentic-start that exists today, and no deployer-side change can make
that pull survive a task restart more than 12 hours after a deploy.** One change
in greentic-start is required before any live ECS worker can serve a bundle
stored in ECR:

> **greentic-start: resolve an ambient ECR credential for `*.dkr.ecr.*`
> references**, the ECR twin of `artifact_registry_token` in
> `src/bundle_ref.rs`. For a reference whose host matches
> `<12 digits>.dkr.ecr[-fips].<region>.amazonaws.com[.cn]`, load AWS
> credentials through the default provider chain (on Fargate this is the ECS
> container credentials endpoint named by
> `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`, i.e. the **task role**), call
> `ecr:GetAuthorizationToken` in the host's region, base64-decode
> `authorizationToken` to `AWS:<password>`, and return `("AWS", <password>)`
> from `resolve_pull_credentials`. Same precedence as the Artifact Registry
> path: an explicit `OCI_USERNAME`/`OCI_PASSWORD` pair still wins, a
> non-ECR host never calls AWS, and a failure degrades to `None` (the registry
> then answers with its own `401`).

Because `seed_pointer::OciBlobPuller` goes through the same
`resolve_pull_credentials`, the change also makes an oversize-seed pointer
(`seed_mode = auto`) pullable from ECR later, at no extra cost.

The change must be released into the image ECS runs
(`ghcr.io/greenticai/greentic-start-distroless`, the floating `develop` tag
unless a digest is pinned), not only into `Dockerfile.tools`.

**What this blocks:** only steps that run a real worker against a bundle in
ECR (the gated live E2E, Task 12 of the phase-1 plan). Tasks 2 to 11 are pure
or call AWS control-plane APIs only and can proceed. Task 12 must not start
until the prerequisite is merged and published, unless it deliberately uses a
registry with long-lived credentials (see "Interim" below).

## 1. What greentic-start supports (evidence)

Read at the commit the designer pins, greentic-start `a3b5ad2c`
(`Dockerfile.tools` `GREENTIC_START_BIN_VER`), and rechecked against
`origin/develop` `d8877c5` (no change to the files below).

### 1.1 Seed (`GREENTIC_SEED_DIR`)

`src/seed_copy.rs`, called from `src/lib.rs` early boot:

- `GREENTIC_SEED_DIR` names a **directory** that mirrors ONE environment's store
  directory: `<seed>/environment.json` and
  `<seed>/.greentic/dev/.dev.secrets.env`. Unset means no-op.
- The tree is copied into `LocalFsStore::default_root()/<GREENTIC_ENV>`
  (`$HOME`-rooted, so `HOME` must be writable; Cloud Run uses `HOME=/tmp`).
  Files land `0600`, written atomically; the source may be read-only.
- Fails the boot (fail closed) when the directory does not exist, is not a
  directory, overlaps the destination, or holds **zero** files.
- Only `environment.json` at the seed root may be a pointer
  (`{"$greentic_seed_pointer":1,...}`, `src/seed_pointer.rs`); it is pulled with
  the same credential rules as the bundle (below).
- **There is no env-var seed.** Nothing in greentic-start reads
  `environment.json` or the dev store from an environment variable. The seed
  must be files.

### 1.2 Bundle pull (`bundle_source_uri`)

`src/revision_pull.rs` + `src/bundle_ref.rs`:

- The pull runs **only on a cold boot with an empty runtime-config**, before the
  HTTP listener binds (`lib.rs` around line 831). There is no hot re-pull; every
  new task cold-boots through this path. Every unit's task pulls every
  **routed** revision of the environment, not only its own (a foreign failure
  is skipped when `GREENTIC_REVISION_ID` is set; its own is fatal).
- Accepted schemes: local path / `file://`, `http(s)://` (anonymous `ureq` GET,
  no auth header), `oci://`, `repo://` (needs `GREENTIC_REPO_REGISTRY_BASE`),
  `store://` (needs `GREENTIC_STORE_REGISTRY_BASE`). **No `s3://`.**
- OCI credentials, `resolve_pull_credentials`:
  1. `OCI_USERNAME` + `OCI_PASSWORD` (both non-empty), read from the **process
     environment** at pull time, i.e. as they were when the container started;
  2. else, only for hosts ending `-docker.pkg.dev`, a token from the GCP
     metadata server (`artifact_registry_token`);
  3. else anonymous (`DefaultRegistryClient::default()`, which reads no
     `~/.docker/config.json`; checked in greentic-distributor-client
     `1.2.0-dev.37753287812`, `oci_packs.rs:564`).
- `GREENTIC_OCI_INSECURE_REGISTRIES` allows plain HTTP for listed registries on
  the digest-gated boot pull only.
- **There is no ECR support at all**: no `ecr`/`amazonaws` match anywhere in
  `src/` at either commit.

## 2. ECS / AWS limits (with sources)

| Fact | Value | Source |
|---|---|---|
| Secrets Manager secret value size | 65,536 bytes; for a string, 65,536 characters. Not adjustable | [Secrets Manager quotas](https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_limits.html) |
| Secrets Manager versions per secret | 100; unlabeled versions beyond 100 are removed, but not ones created in the last 24 h | same page |
| ECS task definition size | 64 KiB, not adjustable | [ECS endpoints and quotas](https://docs.aws.amazon.com/general/latest/gr/ecs-service.html) |
| Containers per task definition | 10 | same page |
| Secret injected as env var | injected when the container **starts**; an update reaches only a new task | [Pass Secrets Manager secrets through ECS environment variables](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/secrets-envvar-secrets-manager.html) |
| Pin a secret version | `valueFrom` = `<secret-arn>:::<version-id>`; needs Fargate platform `1.4.0`+ (whole secret: `1.3.0`+); task **execution** role needs Secrets Manager read | same page |
| `dependsOn` conditions | `SUCCESS` = dependency exits 0; cannot be set on an essential container; Fargate Linux platform `1.3.0`+ | [ContainerDependency](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ContainerDependency.html) |
| Bind mount on Fargate | task-level volume with no `host`; ephemeral storage (20 GiB min, platform `1.4.0`+); shared between containers in the task; data removed when the task stops; default dir `0755` root | [Use bind mounts with Amazon ECS](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/bind-mounts.html) |
| ECR authorization token | valid 12 hours; base64 of `user:password` | [GetAuthorizationToken](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_GetAuthorizationToken.html) |
| One environment string on Linux | `MAX_ARG_STRLEN` = 32 pages = 131,072 bytes | `execve(2)` |

No read-only AWS CLI call was needed for these: they are fixed published
quotas, and listing the demo account would prove nothing about them. Nothing
in account 599558443099 was read or changed.

## 3. Decision: seed delivery

**Chosen mechanism (the default hypothesis, confirmed):** Secrets Manager
secrets injected as environment variables into a small non-essential init
container, which writes `/seed/*` onto a task-level bind-mount volume; the
worker container `dependsOn` it with condition `SUCCESS`.

Task definition shape (per revision):

- Volume: `{"name": "seed"}` (no `host`, so Fargate ephemeral storage).
- Container `seed-init`: `essential: false`, image below, mount `seed` at
  `/seed` read-write, `secrets`:
  - `GREENTIC_SEED_ENVIRONMENT_JSON` = `<env secret arn>:::<version-id>`
  - `GREENTIC_SEED_DEV_STORE` = `<dev-store secret arn>:::<version-id>` (only
    when the environment has a dev store)
  and plain `environment` carrying the expected SHA-256 of each file
  (`GREENTIC_SEED_ENVIRONMENT_JSON_SHA256`, `GREENTIC_SEED_DEV_STORE_SHA256`; a
  digest is not secret). Command, run by `sh`:

  ```sh
  set -eu
  umask 022
  printf '%s' "$GREENTIC_SEED_ENVIRONMENT_JSON" > /seed/environment.json
  echo "$GREENTIC_SEED_ENVIRONMENT_JSON_SHA256  /seed/environment.json" | sha256sum -c -s
  if [ -n "${GREENTIC_SEED_DEV_STORE_SHA256:-}" ]; then
    mkdir -p /seed/.greentic/dev
    printf '%s' "$GREENTIC_SEED_DEV_STORE" > /seed/.greentic/dev/.dev.secrets.env
    echo "$GREENTIC_SEED_DEV_STORE_SHA256  /seed/.greentic/dev/.dev.secrets.env" | sha256sum -c -s
  fi
  ```

  `printf '%s'` writes the variable byte for byte (a shell variable keeps
  trailing newlines; only command substitution strips them). The digest check
  makes a damaged copy exit non-zero, so the worker never starts.
- Container `worker` (essential): mount `seed` at `/seed` **read-only**,
  `dependsOn: [{"containerName": "seed-init", "condition": "SUCCESS"}]`, boot
  env exactly as Cloud Run (`GREENTIC_SEED_DIR=/seed`, `HOME=/tmp`, ...). The
  worker runs as uid 65532 (distroless `nonroot`), so the files must be
  world-readable (`umask 022` gives `0644`); greentic-start copies them to
  `/tmp/.greentic/...` at `0600`. The seed values stay out of the task
  definition (only ARNs are in it), so the 64 KiB task-definition limit is not
  in play.
- Telemetry headers: a third secret, referenced only from the **worker's**
  `secrets` (same names as `HEADER_ENV_NAMES`), never plain `environment`.

Why the alternatives were rejected:

- Seed in plain `environment`: shares the 64 KiB task-definition budget, and is
  readable by anyone with `ecs:DescribeTaskDefinition`.
- Env-var seed read by greentic-start: not supported (section 1.1); would itself
  be a greentic-start change.
- S3 object fetched by an `aws-cli` init container: lifts the size cap but needs
  a large image (slower cold start) and a second credential path. Kept as the
  future answer for seeds the cap refuses, like Cloud Run's `seed_mode = auto`.

### 3.1 Size limit

```rust
/// Largest seed file the ECS lane stages: one Secrets Manager secret value.
pub(crate) const SEED_MAX_BYTES: usize = 65_536;
```

- Applies **separately** to `environment.json` (the pruned
  `seed_environment_bytes(env, &[revision_id])`, the same bytes Cloud Run
  stages) and to the dev store; each is its own secret value.
- Measured in **bytes** before any AWS write. Secrets Manager counts characters
  for a string value; bytes are never fewer than characters, so a bytes check is
  safe (it may refuse a non-ASCII document that would have fit).
- Each value must be valid UTF-8 (`SecretString`) and contain no NUL byte (an
  environment variable cannot carry one). Both seed files satisfy this today:
  `environment.json` is JSON, and the dev store is the text line
  `KEY=<base64>\n` (greentic-secrets-provider-dev `persist`).
- **Failure mode:** over the cap, or not UTF-8, or containing NUL, the warm is
  refused with a named error that names the file, its size and the limit, before
  any secret version or task definition is written. Never truncated, never
  silently split. The cap equals Cloud Run's inline cap, so an environment that
  deploys on Cloud Run inline also fits here.

### 3.2 Version pinning and garbage collection

Each container reference pins a version id, matching Cloud Run's
version-pinned mounts. Secrets Manager removes unlabeled versions beyond 100
(older than 24 h), so a revision that is not redeployed for long enough while
the same secret gains 100 newer versions would lose its pinned version, and its
next task start fails. Task 4/5 must therefore not add a version when the bytes
equal the latest version's (re-warm is then a no-op), and Task 10 must not rely
on version history surviving. This is a known edge, not a blocker.

### 3.3 Init-container image

`public.ecr.aws/docker/library/busybox:1.37.0-musl`, pinned by index digest
`sha256:5cec3fc171c87218698e85a52af7087de727372aae264a787b8112901a5b0092`
(read 2026-10-27 from the public.ecr.aws registry API; linux/amd64 child
`sha256:dc88b80842580654294472735332ec7c7789a4010ec9a68b69f9b88c19abede6`,
linux/arm64 child
`sha256:c542a2b3cb3c982440890284aac884e89dbf468d5ff1c206fd2ba8ea23257420`).
Reasons: a few MB; has `sh`, `printf`, `mkdir`, `sha256sum`; served from ECR
Public, so no Docker Hub rate limit and no credential, the same reachability
assumption as the public GHCR runtime image. Pin the digest in code; never the
bare tag. (The runtime image is distroless, so it cannot do this itself.)

## 4. Decision: bundle pull authentication

**Chosen:** the bundle stays in ECR, and the worker authenticates with the
**task role** through greentic-start's new ambient ECR credential (the external
prerequisite above). Because greentic-start pulls only at cold boot and asks
for the token at pull time, every task, including one ECS starts days after
the last deploy, mints its own fresh 12-hour token. Nothing expires between
deploys.

Deployer obligations once the prerequisite lands:

- The **task role** (not the execution role) gets `ecr:GetAuthorizationToken`
  on `*` plus `ecr:BatchGetImage` and `ecr:GetDownloadUrlForLayer` on the bundle
  repositories. The **execution role** gets `secretsmanager:GetSecretValue` on
  the seed and telemetry secrets (and `kms:Decrypt` if a customer key is used)
  and the log permissions.
- The deployer must **not** set `OCI_USERNAME`/`OCI_PASSWORD` on the worker:
  an explicit pair wins over the ambient token.
- The worker needs network reach to the ECR API and ECR's S3 layer storage
  (public IP, NAT, or the `ecr.api`, `ecr.dkr` and S3 gateway endpoints).

Rejected:

- **ECR token stored in a secret and injected as `OCI_PASSWORD`.** ECS resolves
  the secret when a task starts, so any task started more than 12 hours after
  the token was minted (a crash replacement, a host retirement, a scale-out)
  fails its pull and crash-loops. Keeping it fresh would need a scheduled
  rotator, new infrastructure that still has a window.
- **Init container fetches the bundles.** The worker reads
  `bundle_source_uri` from `environment.json` and pulls every routed revision;
  the init container would have to pull all of them and rewrite the seed to
  `file://` paths, which busybox cannot do safely and which makes the seed
  differ from the store.
- **S3 presigned `https://` URL.** Accepted by greentic-start today, but a
  presigned URL lives at most 7 days, so a later cold start fails.
- **S3 bucket readable anonymously through a VPC endpoint
  (`aws:SourceVpce`).** Works without a greentic-start change and never
  expires, but any workload in that VPC can read every tenant's bundle, and it
  ties the lane to one network layout. Not chosen; recorded as the only
  no-upstream-change option that is not time-bombed.

### Interim (no greentic-start change)

A registry with **long-lived** credentials (for example a GHCR token or a
Harbor robot account) works today: put `OCI_USERNAME`/`OCI_PASSWORD` in a
Secrets Manager secret and reference it from the worker's `secrets`. This is
acceptable for a gated live test. It is not the ECR answer.

## 5. Not verified (must be checked in the live E2E)

Read from documentation and source only; none of it has run on Fargate:

- that data written by a non-essential container that has exited is still on
  the bind mount when the dependent container starts (the documented "share a
  data volume from a source container" case);
- that a `seed-init` exit other than 0 stops the task with a readable reason
  rather than leaving it pending;
- the worker (uid 65532) reading the `0644` files under the root-owned `0755`
  mount;
- the ECR ambient credential path itself (it does not exist yet).

## 6. Roles the operator provides (the deployer grants nothing to them)

The deployer passes two pre-existing roles to ECS (`iam:PassRole`, conditioned
on `ecs-tasks.amazonaws.com`). It never creates them and never attaches
permissions to them; the bootstrap Terraform and README say the same.

- **Execution role** (`execution_role_arn`): `secretsmanager:GetSecretValue`
  on the seed secrets (ECS resolves the task definition's `secrets` entries
  with this role before any container starts), `logs:CreateLogStream` and
  `logs:PutLogEvents` on the deployment's log group, and pull access for the
  runtime image. The public GHCR runtime image and the busybox init image need
  no registry permission; a private registry does.
- **Task role** (the identity greentic-start runs as): read access to the
  bundle registry per section 4 -- for ECR, `ecr:GetAuthorizationToken` on `*`
  plus `ecr:BatchGetImage` and `ecr:GetDownloadUrlForLayer` on the bundle
  repositories.

The deployer's own role needs no ECR permission at all: nothing in the deployer
pushes an image (`ecr:PutImage` was removed from the validated verbs).
