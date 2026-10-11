# Native Linux host deployment (HOME-03)

The opt-in `single-vm host-plan` and `single-vm host-apply` commands consume
`greentic-types = 1.2.38173118925`, released from types PR #214 (merge
`d6b38898f392ab26f75c706aa962c17cc301cf97`). Existing single-VM commands retain
their v1 format and x86-64 restriction. The new format wraps that deployment in
`HostSingleVmSpec { schema_version: "1.0.0", deployment, host }`; `host` is the
published `greentic_types::deployment::host::HostRequirements` contract.
Unknown fields and unsupported combinations fail before launch.

## Commands and authority

```sh
sudo greentic-deployer single-vm host-plan --spec /etc/greentic/home.spec.json --policy /etc/greentic/home.policy.json
sudo greentic-deployer single-vm host-apply --spec /etc/greentic/home.spec.json --policy /etc/greentic/home.policy.json
sudo greentic-deployer single-vm host-apply --spec /etc/greentic/home.spec.json --policy /etc/greentic/home.policy.json --execute
```

The first two commands perform the same read-only native preflight. Execute
repeats it under an exclusive service lock, then rechecks policy, artifact and
mapping identity immediately before restart. Serialized plans cannot authorize
apply. These commands use the local Docker Unix socket, systemd and local mTLS
health checks; they do not load cloud credentials or pull images.

A separately provisioned root-owned policy approves the **complete** request:

```json
{
  "schema_version": "1.0.0",
  "approved": "REPLACE WITH THE COMPLETE HostSingleVmSpec OBJECT",
  "workload_uid": 1000,
  "workload_gid": 1000,
  "storage_contract": "operator-reviewed-data-format-v1",
  "bundle_sha256": "REPLACE WITH THE STAGED BUNDLE SHA256",
  "health_client_certificate": "/etc/greentic/health-client.crt",
  "health_client_key": "/etc/greentic/health-client.key"
}
```

This illustrative policy is deliberately not runnable until its placeholders
are replaced. `ci/host-qualification/qualify.py` constructs a complete runnable
service-only example. Policy/credential paths and every ancestor must be
root-owned, free of symlinks and not writable by group/others. The client key is
root-only. A pack's host request never grants access by itself.

## Supported host matrix and provisioning

| Primitive | Supported boundary |
| --- | --- |
| OS/architecture | Native Linux aarch64 or x86_64, matching the staged Docker image; foreign architecture denied |
| Network | Explicit bridge or host; none unsupported by this adapter's mTLS health contract |
| Devices | Existing individual character devices, group-readable or group-read/write; stable serial aliases resolve to canonical device nodes; no mknod permission |
| Sockets | Only an explicitly approved `/run/dbus/system_bus_socket` bind; engine/control sockets denied |
| Mounts | Existing protected directories with declared ownership; writable paths owned by the non-root workload UID/GID |
| Ports | Bounded typed TCP/UDP mappings; admin TCP 8433 must remain host-loopback-only |
| Health | Bounded HTTPS readiness on loopback 8433 with explicit CA and client identity, no proxy or redirects |

Provision local immutable image digests (registry `@sha256:` or Docker image
`sha256:` IDs), a local regular SquashFS bundle, all four persistent directories,
the derived `/mnt/greentic/bundles/<deployment>` directory, and mTLS credentials
before planning. The bundle must match the approved SHA256 and be at most
512 MiB. Public credentials and bundle are protected root-owned regular files
readable by the workload. The server key is root-owned, workload-group-readable
and inaccessible to others. The bundle mount directory is root-owned and
traversable/readable by the workload. Root-owned protected ancestors prevent
workload replacement of native mappings.

The systemd supervisor runs as root to access Docker; the container always uses
the policy's nonzero UID/GID, a read-only root filesystem, all capabilities
dropped, no-new-privileges and `--pull never`. Device group IDs are added only
for approved mappings. D-Bus access still requires host-side bus authorization;
this adapter does not install Bluetooth policy or certify a controller. Bridge
mode listens on the container interface while publishing admin only to host
127.0.0.1. Host networking must be explicitly approved and has no Docker port
isolation; the runtime must honor its loopback admin configuration.

## Failure, rollback and migration

Atomic, fsynced service-file writes and a protected journal under
`/var/lib/greentic-deployer` preserve the previous unit, environment, installed
record and enabled/active state. Failed startup/readiness restores those files
and service state. An incomplete recovery retains the journal for the next
apply. A restart request is not a readiness claim: the qualification runner
also waits for the restored service's mTLS endpoint.

Persistent workload directories are never deleted, recursively chowned or
restored from a service backup. The `storage_contract` must match the installed
record; incompatible updates/downgrades and unmanaged existing service units
require a separate explicit migration. Operators must ensure images with the
same contract remain data-compatible. This service transaction does not claim
to roll back arbitrary data migrations or physical IoT operations.

## Qualification

Unit tests cover strict parsing, unsafe mappings, architecture and policy
mismatch, protected paths, storage compatibility, pre-launch changes, atomic
rollback and recovery journals. `ci/host-qualification/stage.sh` is restricted
to a dedicated disposable ARM64 Linux machine and refuses an existing fixture.
It stages immutable simulator images, a real SquashFS bundle and ephemeral
mTLS credentials. Then run `sudo python3 ci/host-qualification/qualify.py
/absolute/path/to/greentic-deployer` on that host.

The native test exercises Docker/systemd apply, real mTLS readiness, failed
update rollback and a persistent boot counter; it also rejects missing serial
hardware, unknown privileges, foreign architecture, changed bundle digest,
wrong storage ownership and incompatible data contracts. Credentials stay on
the disposable host. This is generic ARM64 service-only evidence, not Raspberry
Pi, Zigbee, Matter, BLE or physical-command qualification.
