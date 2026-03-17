# Single VM V1 Direction

This document captures the current product direction for the open-source deployer.

## Current Scope Decision

The latest clarified product boundary is:

- OSS / public deployer: single VM only
- Commercial / private deployer: all other deployment targets

That means:

- `greenticai/greentic-deployer` should focus on a single-VM deployment product
- `greentic-biz/greentic-deployer` should own HA, cloud, Kubernetes, Juju, Snap, Terraform, and serverless adapters

If older docs mention broader OSS support, prefer this decision.

## Platform Matrix Clarification

The team clarified that CLI/desktop packaging is separate from server deployment.

CLI/desktop variants:

- Windows x86_64
- Windows ARM
- macOS Intel
- macOS ARM
- Linux x86_64
- Linux ARM

OSS single-VM server deployment variants:

- Linux x86_64

So for this repo and this product path:

- single-vm OSS deployer should target Linux only
- supported server architecture in v1 is `x86_64`
- Windows and macOS belong to CLI/desktop packaging, not server deployment
- Linux `aarch64` can be added later if needed

## What OSS Should Do

The OSS deployer should support:

- `plan`
- `apply`
- `destroy`

For one target only:

- `single-vm`

The single-vm deploy flow should:

- deploy one active bundle
- use a readonly bundle mount
- keep writable runtime dirs separate
- expose localhost-only admin HTTPS
- require mTLS for admin access
- run with static MUSL-linked runtime artifacts
- support Linux `x86_64`
- prefer one container runtime path where practical

## What OSS Should Not Do

The OSS deployer should not implement in v1:

- HA deployment
- cloud provider orchestration
- Kubernetes orchestration
- Terraform generation as a productized adapter
- Juju
- Snap
- Serverless
- multi-bundle deployment

These belong to `greentic-biz/greentic-deployer`.

## Recommended Architecture

Split the solution into three layers.

### Runtime

Responsible for:

- opening squashfs bundles
- readonly bundle access
- writable runtime dirs
- wasm/cwasm caching
- health/readiness
- localhost mTLS admin endpoint

### Deployer Core

Responsible for:

- desired-state deployment spec
- plan/apply/destroy orchestration
- current-state tracking
- reconciliation logic

### Adapter

OSS should implement only:

- `single-vm`

The adapter should generate and/or apply:

- filesystem layout
- service definitions
- runtime launch config
- admin cert layout

Current execution preference:

- one container per deployment
- Docker or Podman, whichever is easier
- keep `plan -> apply -> converge -> run` semantics close to Terraform-style workflow

## Deployment Spec V1 Draft

The initial source of truth should be a versioned deployment spec for single VM only.

Example:

```yaml
apiVersion: greentic.ai/v1alpha1
kind: Deployment
metadata:
  name: acme-prod
spec:
  target: single-vm
  bundle:
    source: file:///opt/greentic/bundles/acme.squashfs
    format: squashfs
  runtime:
    image: ghcr.io/greentic-ai/operator-distroless:0.1.0-distroless
    arch: x86_64
    admin:
      bind: 127.0.0.1:8433
      mtls:
        caFile: /etc/greentic/admin/ca.crt
        certFile: /etc/greentic/admin/server.crt
        keyFile: /etc/greentic/admin/server.key
  storage:
    stateDir: /var/lib/greentic/state
    cacheDir: /var/lib/greentic/cache
    logDir: /var/log/greentic
    tempDir: /var/lib/greentic/tmp
  service:
    manager: systemd
    user: greentic
    group: greentic
  health:
    readinessPath: /ready
    livenessPath: /health
    startupTimeoutSeconds: 120
  rollout:
    strategy: recreate
```

## Filesystem Contract

The bundle should be immutable input.

Writable directories should be explicit and separate:

- `/var/lib/greentic/state`
- `/var/lib/greentic/cache`
- `/var/lib/greentic/tmp`
- `/var/log/greentic`

Do not write into the mounted bundle.

## Admin Endpoint Rules

These are hard requirements:

- bind only to `127.0.0.1`
- never bind to `0.0.0.0:8433`
- use HTTPS
- require mTLS client certificates

Reuse the operator admin HTTPS + mTLS model where practical, but keep deployer/runtime responsibilities clear.

## Packaging Direction

Runtime packaging should use:

1. a Debian-based builder image
2. a distroless final image

The final runtime should contain only the MUSL-linked artifacts required to run bundles.

No dynamic libraries should be required at runtime.

## Suggested Initial Module Layout

For this repo, the next implementation step should introduce or formalize modules in this direction:

- `src/spec.rs`
- `src/state.rs`
- `src/plan.rs`
- `src/apply.rs`
- `src/destroy.rs`
- `src/adapters/single_vm.rs`

If the existing generic planner model is retained, the single-vm OSS contract should still become the explicit product-facing path.

## Immediate Next Steps

1. Define `DeploymentSpec v1` as Rust types.
2. Add validation rules and defaults for single VM.
3. Define the single-vm state model.
4. Define the single-vm output artifacts:
   - service units or launch definitions
   - cert paths
   - mounted bundle path
   - writable dir layout
5. Implement `plan` for single VM.
6. Implement `apply` for single VM.
7. Implement `destroy` for single VM.
8. Add e2e for single VM.

## Open Questions

These still need explicit decisions before implementation goes too far:

1. exact apply scope:
   - materialize files only
   - or also pull/restart/enable runtime
2. exact location of runtime state
3. exact admin API schema
4. exact bundle mounting flow on VM
5. whether the current deployment-pack abstraction remains the main execution model for OSS single-vm v1
