# greentic-deploy-spec

Schema crate for Greentic's deployment object model. Defines:

- `Environment` (§5.1) + `EnvironmentHostConfig` + `EnvPackBinding` + `CapabilitySlot` + `PackDescriptor`
- `EnvironmentRuntime` (§5.1a)
- `Revision` (§5.2) + `RevisionLifecycle` + transition predicate
- `TrafficSplit` (§5.3) + basis-points validator
- `BundleDeployment` (§5.4) + revenue-share validator
- `Credentials` (§5.5)
- `PackConfig` (§5.6) — `non_secret` + `secret_refs` + `runtime_refs`
- `RuntimeConfig` (§5.7) + `RevisionRuntimeBlock`

This crate is the single owner of these schemas. Other crates depend on it; nothing in this crate
depends on operational/runtime code. JSON-schema generation is gated behind the `schemars` feature
and a thin `gen-schemas` binary.

See `plans/next-gen-deployment.md` §5 for the design rationale.
