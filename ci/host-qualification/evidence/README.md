# HOME-03 native execution evidence

`linux-arm64-summary.json` is captured output, not an expected-result fixture.
Run date: 2026-10-11. Host: isolated Lima 2.2.1 Apple Virtualization ARM64 VM,
Ubuntu 24.04, Linux 6.8.0-142-generic, Docker native linux/aarch64. Only the
qualification input directory was mounted from macOS, read-only. No physical
Pi, coordinator or sensor was attached.

The deployer was built with Rust 1.95.0, cargo-zigbuild 0.19.7 and Zig 0.14.1:

```sh
cargo zigbuild --locked --target aarch64-unknown-linux-gnu.2.35 --bin greentic-deployer --jobs 4
```

The executable, bundle and both Docker image identities are in the summary.
`stage.sh` staged the fixture and ephemeral local mTLS credentials. The actual
native invocation was:

```sh
sudo python3 /mnt/iot-home-share/host-qualification/qualify.py /usr/local/bin/greentic-deployer-home03
```

Exit 0. Verified cases: identical preview/plan output, real D-Bus socket
preflight, strict unknown privilege rejection, wrong bundle digest, foreign
architecture, missing serial path, incorrect persistent ownership, bridge
apply, host-network apply, restoration to bridge, failed-readiness update
rollback and incompatible storage-contract rejection. Persistent boot count
increased from 7 to 11 across network updates and failed-update recovery; the
restored service became healthy with the original immutable image.

The first run exposed a qualification-harness race: systemd restart returns
before application readiness. The runner now waits at most 15 seconds for
restored mTLS readiness instead of immediately issuing a single curl request.
The deployer's successful apply already waits for bounded mTLS readiness.

Full per-case stdout/stderr remains on the VM under
`/opt/iot-home03-qualification/reports`; only nonsecret summary data is checked
in. Certificates are short-lived test identities. This evidence establishes
generic host service behavior, not IoT command safety or physical qualification.
