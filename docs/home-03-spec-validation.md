# HOME-03 deployment specification validation

The existing `greentic.ai/v1alpha1` single-VM specification now rejects unknown
fields at every object boundary. For example, `runtime.privileged: true` and an
unimplemented `spec.host` block fail parsing rather than being silently ignored.
This is an intentional tightening: remove misspelled or unsupported fields;
there is no compatibility switch that treats them as granted host access.

Values rendered into systemd units, Docker arguments and environment files are
validated before planning. Names and identities have bounded ASCII token syntax;
images and remote bundle references reject whitespace, quoting and expansion.
Filesystem paths must be literal absolute paths without traversal, mount options,
shell/systemd expansion or control characters. Local bundle sources support
absolute paths and `file://`; remote references support `https://` and `oci://`
with the same restricted literal syntax. Signed URLs with query strings are not
supported by this renderer. Stage those artifacts locally instead. Admin binds
must exactly match the supported loopback forms, without trimming. Health paths
are literal absolute paths (including `/`) and startup timeouts are 1–300 seconds.

The checks run for JSON/YAML parsing and for in-memory specs passed to the
single-VM planner. They prevent text injection; they do not authorize access to
any host file, prove ownership, resolve symlinks or validate image availability.
Direct rendering and applying of caller-constructed `SingleVmPlanOutput` remain
trusted library interfaces and still need the HOME-03 enforcement integration.

ARM64 is still rejected. Shared host requirements are proposed in
[greentic-types HOME-03 PR #214](https://github.com/greenticai/greentic-types/pull/214).
After a compatible release, deployer must consume that contract and enforce
operator-owned access policy and fresh native facts consistently at preview,
plan and apply. Architecture/device checks, storage ownership, transaction-safe
apply/rollback and real Linux ARM64 evidence are required before HOME-03 is
complete. This increment neither duplicates the shared contract nor grants
privileges from a pack.

On macOS, run the full check with `TMPDIR=/private/tmp bash ci/local_check.sh`.
The default `/var/folders/...` temp path passes through the `/var` symlink;
operator signing-key tests correctly reject symlinks in key ancestors. Using
the real temporary directory keeps those checks enabled. The first full run
exposed that environment issue and an existing path-error diagnostic expectation;
the latter is preserved by the validation change.
