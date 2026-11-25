# Cloud Run encrypted secret-store transport v1

The environment's encrypted dev-store file is a complete byte stream, not a
collection of independently migratable worker secrets. Workspace-admin loading
can reduce it, but bootstrap records and credentials legitimately remain. A
70,737-byte file cannot fit a 65,536-byte Secret Manager version.

Verified against deployer develop `0ced1a6`: `create_revision` stages
`environment.json` and `.greentic/dev/.dev.secrets.env` as distinct versions of
one environment-owned secret. The dev store was uploaded monolithically.
`seed_mode=auto` only externalizes **environment.json** to OCI; it does not
externalize the encrypted dev store. The transport preserves every byte passed
by the CLI after its existing deployer-credential isolation filter; it adds no
record removal or migration and retains worker/channel/bootstrap records.
`runtime_secrets.rs` and
`runtime_secret_sink.rs` resolve/promote individual secrets on the legacy IaC
path; they do not transport this Cloud Run env-pack seed file.

## Wire contract

The shared owner is `greentic-deploy-spec::secret_chunks`, schema
`greentic.secret-store.chunks.v1`.

- Up to and including **65,536 bytes**, use the legacy single numeric version
  mounted at `/seed/.greentic/dev/.dev.secrets.env`, byte for byte.
- Larger files use **61,440-byte chunks**, with at most **64 chunks** and a
  total capacity of **3,932,160 bytes** in this protocol version. This explicit
  resource/allocation bound is an implementation limit, not a claim of a
  Cloud Run quota. Exceeding it fails; nothing is truncated or compressed away.
- Chunk `i` is mounted at
  `/seed/.greentic/dev/.dev.secrets.chunks.v1/000000.bin` (six decimal digits).
- The manifest is mounted at
  `/seed/.greentic/dev/.dev.secrets.chunks.v1.json`. It contains `schema`, the
  full encrypted byte `length` and SHA-256, and ordered `chunks` entries with
  `index`, canonical relative `path`, immutable numeric `version`, byte
  `length`, and SHA-256.
- The manifest is uploaded **last** to a separate immutable version. Its
  own version is pinned in the volume's items. No `latest` or version alias
  is accepted, and chunk versions must be distinct.

Chunk size, canonical paths, count bound and manifest validation are fixed v1
wire semantics. Incompatible changes require a new schema/capability version;
never increase the producer's capacity while still claiming compatibility with
an older runtime's `=1` label.

All versions belong to the existing environment-owned secret. This preserves
one accessor grant, owner stamping, and one `/seed` volume. Distinct item paths
avoid nested volume mounts. Multiple resources would multiply IAM grants and
ownership/race handling without improving the per-version payload limit. The
[Cloud Run v2 volume API](https://docs.cloud.google.com/run/docs/reference/rest/v2/Volume)
supports explicit version-to-path entries within a single secret volume.

Every upload, including environment JSON, manifests, telemetry and Redis
payloads, is checked for the 1..=65,536-byte bound before the real API call.
The fake enforces the same rule. Runtime hash verification catches missing,
truncated, corrupt or swapped chunk content; manifest validation rejects
unknown schemas/fields, noncanonical paths, duplicate versions, reordered or
missing entries, invalid hashes and inconsistent lengths. Parsing/I/O failures
never include secret payloads or serde's offending values.

## Runtime capability gate

No operator boolean can authorize chunking. Before any seed/artifact upload,
secret claim, grant or service update for an oversized store, deployer verifies:

1. The **effective image of that revision** is `repository@sha256:<64 hex>`.
   A revision's own pin overrides a binding's image answer. Tags do not qualify.
2. Fetch the OCI image manifest/config, selecting **linux/amd64** for an index,
   matching [Cloud Run's container contract](https://docs.cloud.google.com/run/docs/container-contract).
   Match the manifest/index digest to the pin
   and hash the config bytes against the manifest's config descriptor.
3. The verified config has `os=linux`, `architecture=amd64`, and label
   **`io.greentic.secret-store.chunks=1`**. Missing, malformed, unsupported or
   unverifiable capabilities fail closed before seed writes.

Artifact Registry inspection uses the bound GCP identity; its token is never
sent to arbitrary registries. Other registries are queried anonymously, so a
private non-AR runtime registry currently fails closed unless it is readable
anonymously. Authentication/registry errors are replaced with static safe
messages. Capability fetching has bounded connect/read timeouts and a 60-second
operation deadline; a stalled registry cannot proceed to seed staging. Existing
registry permissions must permit reading the pinned image
manifest and config; this change does not grant wider registry IAM.

The coordinated greentic-start source changes add this label to the distroless
runtime stage, inherited by its variants. It is a release assertion about that
image's compiled boot implementation; do not label older runtime binaries.

## Runtime boot, retry and rollback

Chunked revisions set `GREENTIC_SECRET_STORE_TRANSPORT=greentic.secret-store.chunks.v1` as part of their immutable revision intent. The runtime requires the manifest when this marker is present, including when the entire chunk mount is missing. Unknown marker values fail closed without echoing their contents. Legacy revisions omit the marker.

The matching start implementation verifies the chunk manifest and every chunk
**before overlaying the seed tree or opening the store**. Reads and allocations
are bounded. Source symlinks, redirected parent directories, extra chunk files,
missing manifests, and simultaneous legacy/chunked stores are refused.

Transport files are not copied into the writable runtime tree. The full
verified encrypted buffer is installed as the original `.dev.secrets.env`
using the existing exclusive sibling-temp/rename path: file mode 0600,
private dev directory mode 0700, and `sync_all` before rename. Bad mounts leave
an existing secret file and environment untouched and fail boot/readiness;
there is no memory backend fallback or silently accepted partial store.
Legacy file-only seeds still copy exactly as before, including rollback from
chunked to legacy and subsequent upgrade back to chunks.

Partial uploads leave unreferenced immutable versions; they publish no usable
manifest/service template. A retry stages a fresh complete set. No seed
versions are destroyed or disabled, including previous rollback versions. Any
future seed garbage collection must retain every chunk transitively referenced
by all active and rollback manifests, not just the manifest versions themselves.
Service upsert only follows complete staging, retains existing traffic, and
adds a candidate at zero percent. Readiness and invoker policy ordering stay
unchanged. An already-created same-intent immutable revision keeps its pinned
seed on retry; changing transport or secret contents needs a **new logical
revision**, never credential rotation under an old identity.

## Designer handover and release dependencies

The deployer capability probe is:

```sh
greentic-deployer op --store-root <store> env capabilities local
```

For Cloud Run, require `result.secret_store_transport` with:

```json
{
  "schema": "greentic.secret-store.chunks.v1",
  "legacy_max_bytes": 65536,
  "chunk_bytes": 61440,
  "max_chunks": 64,
  "max_store_bytes": 3932160,
  "runtime_image_capability_label": "io.greentic.secret-store.chunks",
  "runtime_image_capability_value": "1",
  "requires_verified_digest_pin": true,
  "live_deploy": true
}
```

Do **not** remove the existing 65,536-byte guard for old deployers or runtimes.
Replace it only after these coordinated artifacts exist:

1. Publish **greentic-deploy-spec** carrying `secret_chunks` and **deployer**
   carrying the capability report, image verification and staging path from
   this feature branch. Record their exact immutable package versions and
   CLI artifact checksums. The base `1.2.0-dev.0` version string is insufficient.
2. Raise start's deploy-spec **and deployer** dependency floors and lockfile to the
   matching **published protocol releases**, build start with the reconstruction code, and publish
   its distroless image. Record the runtime release/source commit, the exact
   OCI index or linux/amd64 manifest digest and verified config capability.
   Current published spec releases do not expose the new API: the runtime
   source is validated with a temporary local protocol overlay, not a
   committed path override. It is not independently releasable until this
   dependency/pin step is completed. Validation copies use the existing
   dependency version solely to satisfy Cargo's resolver; that does not claim
   the already-published version contains the new protocol. Never use the old
   run ID as the compatibility floor for release.
3. Update Designer's pinned **deployer binary/build** and every effective
   **per-revision runtime image digest** together. Rebuild/pin any containing
   tools image. Current deployed pins have not been changed by this work.
4. After all secret staging/purging has finished, measure the exact final
   encrypted file bytes. At <=65,536, retain the legacy path. Above it,
   require the deployer capability object, `live_deploy=true`, every affected
   runtime's verified label at its effective digest, and `length <=
   max_store_bytes`. Check `ceil(length/chunk_bytes) <= max_chunks` and the
   manifest/version-to-path plan (one volume, unique canonical paths, numeric
   immutable versions, manifest <=65,536). The deployer remains the final
   authoritative verifier; preflight must not silently downgrade its refusal.
5. Stage new logical revisions. Keep the operation within Designer's normal
   env-up snapshot/cleanup boundary. Do not add a separate mutating apply,
   discard retry checkpoints, delete old seed versions, or change live
   traffic on failed staging/readiness.
6. Show operators safe size/chunk counts, protocol/capability failures and
   which worker's effective image lacks support. Never print secret values,
   mounted content, auth headers or upstream registry bodies.

No compatible deployer/runtime package versions or image digests have been
published by this task. Those exact artifact pins must be recorded from the
coordinated release outputs before Designer enables large-store deployment;
there is deliberately no invented minimum nightly/run ID or runtime digest.

## Independent secrets-door diagnostics

Workspace-admin loading is a policy/placement optimization, not a capacity
protocol. In the previously deployed path, no nominated worker means
`flagged.is_empty()` returns before the `secrets-door` step is recorded. Any
unflagged worker needs embedded shared/channel credentials, so those records
stay for **all** workers. A worker with only shared secrets has no private
credential to mirror and can fail nomination despite legitimately needing
central loading. Bootstrap/interop documents, signing material and unmigrated
categories can remain even when every eligible worker is flagged.

Designer must always report the placement decision for each worker and channel:
no private eligible credentials/shared-only nomination; admin mirror or probe
refusal; unsupported runtime; failed key or worker-settings staging; restored
embedded fallback; and the specific unflagged workers retaining shared/channel
records. Report only identities, categories, reasons and sizes/counts.

The current local Designer tree already contains `cloud_apply/door_diagnostics.rs`
and related tests describing these cases; that does not prove they are in a
particular deployed Designer image. Audit its actual release pin separately.
Correct nomination and diagnostics are useful independent work. They cannot
remove the Secret Manager per-version limit or replace this transport.


## Validation and delivery status (2026-11-25)

No production services, IAM, secret versions or credentials were changed.
Cloud/Redis/NATS live-test flags were unset and Docker was disabled. Tests used
synthetic encrypted-byte buffers, in-memory targets and local fixture servers;
there was no live Cloud Run deployment.

| Check | Result |
|---|---|
| Deployer `bash ci/local_check.sh` | Passed: formatting, strict all-target/all-feature Clippy, scaffolds, fixture packs, all tests, documentation and no-default-features build. Includes 3,010 deployer unit tests and 300 deploy-spec unit tests; integrations/doctests also passed. |
| Runtime formatting and strict all-target/all-feature Clippy | Passed with the matching local source overlay. |
| Runtime full all-feature tests | 3,421 unit tests passed, 27 ignored, two unrelated network tests failed; all 22 seed-copy tests passed. |
| Runtime tests excluding the two documented failures | Passed: 3,421 unit tests, all integrations and doctests; two explicitly filtered out. |
| Runtime all-feature build, documentation, package creation and package verification | Passed with the local source overlay. This is source-cohort validation, not independent published-package readiness. |

The two runtime failures reproduce individually in untouched tests:

- `interop::metering::sink::sink_tests::a_refused_connection_is_a_connect_failure_and_says_so`: this host reports `ConnectTimeout` where the test expects `Connect`.
- `revision_serve::interop_ingress_tests::an_unauthenticated_a2a_post_is_refused_before_its_body_is_read`: reading the fixture response returns `ConnectionReset`.

The runtime's full `ci/local_check.sh` therefore remains failing at its test
step. Build/doc/package steps were checked separately afterward; publish dry-run
and the release/binstall smoke step were not reached. No unrelated network
behavior was changed to make this feature appear green.

The regressions cover 65,536-byte legacy storage; 65,537 and the reported
70,737-byte chunked stores; incompressible stores over 2 MiB; v1's maximum;
byte-for-byte reconstruction; missing/corrupt/swapped/reordered/duplicate chunks;
missing manifests and entire mounts; unsupported protocols and image capability
mismatches; partial uploads, immutable retries and legacy rollback; private
atomic installation; and diagnostics that do not echo injected credential text.
The SDK rendering test verifies all exact version/path entries share one mount.

Temporary Cargo patches were removed and start's original lockfile restored.
No path override or fabricated release floor is included in the source changes.
The generated deployer repository overview was refreshed with the shared codec,
staging/gate module and this handover. Required release artifacts and Designer
pin/guard changes above remain dependencies; nothing has been published or
redeployed by this task.

Companion runtime source: `greentic-start` branch
`fix/cloudrun-chunked-secret-store`, commit `dd7fe6e2f8b26ecd3069be5e10feb5ad737e6bec`
(worktree `/private/tmp/greentic-start-chunked`). This is a source pin, not a
published runtime release or OCI image digest.
