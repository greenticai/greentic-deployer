"""Run only on the dedicated ARM64 fixture host after stage.sh.

Exercises the actual deployer/Docker/systemd/mTLS boundary. This is service-only
simulator evidence, not Raspberry Pi or peripheral/IoT-command qualification.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

if os.geteuid() != 0 or os.uname().machine != "aarch64":
    raise SystemExit("requires the disposable ARM64 Linux fixture host as root")
binary = Path(sys.argv[1]).resolve()
root = Path("/opt/iot-home03-qualification")
reports = root / "reports"
reports.mkdir(exist_ok=True)
good_image = (root / "good-image.txt").read_text().strip()
bad_image = (root / "bad-image.txt").read_text().strip()
storage = {name + "Dir": "/var/lib/iot-home03/" + directory
           for name, directory in [("state", "state"), ("cache", "cache"), ("log", "logs"), ("temp", "temp")]}
deployment = {
    "apiVersion": "greentic.ai/v1alpha1", "kind": "Deployment",
    "metadata": {"name": "iot-home03-simulator"},
    "spec": {
        "target": "single-vm",
        "bundle": {"source": "file://" + str(root / "simulator.squashfs"), "format": "squashfs"},
        "runtime": {"image": good_image, "arch": "aarch64", "admin": {
            "bind": "127.0.0.1:8433", "mtls": {
                "caFile": "/etc/greentic/admin/ca.crt", "certFile": "/etc/greentic/admin/server.crt",
                "keyFile": "/etc/greentic/admin/server.key"}}},
        "storage": storage, "service": {"manager": "systemd", "user": "root", "group": "root"},
        "health": {"readinessPath": "/ready", "livenessPath": "/health", "startupTimeoutSeconds": 10},
        "rollout": {"strategy": "recreate"},
    },
}
spec = {"schema_version": "1.0.0", "deployment": deployment, "host": {
    "schema_version": "1.0.0", "os": "linux", "architecture": "aarch64", "network": "bridge",
    "devices": [], "sockets": [], "mounts": [
        {"source": path, "target": path, "read_only": False, "owner_uid": 1000, "owner_gid": 1000}
        for path in storage.values()],
    "ports": [{"host_port": 8433, "workload_port": 8433, "protocol": "tcp", "bind": "loopback"}],
    "health": {"port": 8433, "path": "/ready", "startup_timeout_seconds": 10},
}}
policy = {"schema_version": "1.0.0", "approved": spec, "workload_uid": 1000, "workload_gid": 1000,
          "storage_contract": "host-qualification-v1",
          "bundle_sha256": hashlib.sha256((root / "simulator.squashfs").read_bytes()).hexdigest(),
          "health_client_certificate": "/etc/greentic/health-client.crt",
          "health_client_key": "/etc/greentic/health-client.key"}


def run(case, request, operator, execute=False, error=None, preview=False):
    request_path = Path("/etc/greentic") / (case + ".spec.json")
    policy_path = Path("/etc/greentic") / (case + ".policy.json")
    request_path.write_text(json.dumps(request, indent=2))
    policy_path.write_text(json.dumps(operator, indent=2))
    request_path.chmod(0o600)
    policy_path.chmod(0o600)
    command = [str(binary), "single-vm", "host-apply" if execute or preview else "host-plan",
               "--spec", str(request_path), "--policy", str(policy_path)]
    if execute:
        command += ["--execute"]
    result = subprocess.run(command, text=True, capture_output=True, timeout=150)
    (reports / (case + ".stdout")).write_text(result.stdout)
    (reports / (case + ".stderr")).write_text(result.stderr)
    if error:
        assert result.returncode != 0 and error in result.stderr, (case, result.returncode, result.stderr)
    else:
        assert result.returncode == 0, (case, result.stderr)
        json.loads(result.stdout)
    return result


planned = run("plan", spec, policy)
previewed = run("preview", spec, policy, preview=True)
assert json.loads(planned.stdout) == json.loads(previewed.stdout)
dbus = copy.deepcopy(spec)
dbus["host"]["sockets"] = [{"source": "/run/dbus/system_bus_socket", "target": "/run/dbus/system_bus_socket"}]
run("dbus-plan", dbus, {**policy, "approved": dbus})
unknown = copy.deepcopy(spec)
unknown["host"]["privileged"] = True
run("deny-privileged", unknown, policy, error="unknown field")
run("deny-bundle-digest", spec, {**policy, "bundle_sha256": "0" * 64}, error="bundle digest")
foreign = copy.deepcopy(spec)
foreign["host"]["architecture"] = foreign["deployment"]["spec"]["runtime"]["arch"] = "x86_64"
run("deny-architecture", foreign, {**policy, "approved": foreign}, error="native Linux/x86_64")
missing = copy.deepcopy(spec)
missing["host"]["devices"] = [{"source": "/dev/serial/by-id/home03-missing", "target": "/dev/home03", "access": "read_write"}]
run("deny-missing-device", missing, {**policy, "approved": missing}, error="No such file")
os.chown(storage["stateDir"], 1001, 1000)
try:
    run("deny-storage-owner", spec, policy, error="persistent mount")
finally:
    os.chown(storage["stateDir"], 1000, 1000)
run("apply", spec, policy, execute=True)


def health():
    deadline = time.monotonic() + 15
    while True:
        result = subprocess.run(["curl", "--fail", "--silent", "--show-error", "--noproxy", "*",
                             "--cacert", "/etc/greentic/admin/ca.crt", "--cert", policy["health_client_certificate"],
                             "--key", policy["health_client_key"], "https://127.0.0.1:8433/ready"],
                                capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            return json.loads(result.stdout)
        if time.monotonic() >= deadline:
            raise AssertionError("restored service did not become healthy: " + result.stderr)
        time.sleep(0.1)


before = health()
host_network = copy.deepcopy(spec)
host_network["host"]["network"] = "host"
run("host-network-apply", host_network, {**policy, "approved": host_network}, execute=True)
assert health()["healthy"]
run("bridge-network-restore", spec, policy, execute=True)
bad = copy.deepcopy(spec)
bad["deployment"]["spec"]["runtime"]["image"] = bad_image
run("failed-update", bad, {**policy, "approved": bad}, execute=True, error="previous service files/state restored")
after = health()
assert before["healthy"] and after["healthy"] and after["boots"] > before["boots"]
run("deny-storage-downgrade", spec, {**policy, "storage_contract": "incompatible-v0"}, error="migration")
unit = Path("/etc/systemd/system/iot-home03-simulator-greentic-runtime.service").read_text()
assert good_image in unit and bad_image not in unit
assert "--user 1000:1000" in unit and "--cap-drop ALL" in unit and "--pull never" in unit
summary = {"scope": "generic Linux ARM64 service-only simulator", "kernel": os.uname().release,
           "architecture": os.uname().machine, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
           "bundle_sha256": policy["bundle_sha256"], "good_image": good_image, "bad_image": bad_image,
           "before_failed_update": before, "after_rollback": after,
           "result": "passed", "physical_iot_qualification": False}
(reports / "summary.json").write_text(json.dumps(summary, indent=2))
print(json.dumps(summary, indent=2))
