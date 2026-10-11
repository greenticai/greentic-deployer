#!/usr/bin/env bash
# Run only on a dedicated, disposable Linux ARM64 qualification host as root.
# Secrets stay on that host. This prepares artifacts; it does not deploy them.
set -euo pipefail
test "$(uname -s)" = Linux
test "$(uname -m)" = aarch64
test "$(id -u)" = 0
fixture_root=/opt/iot-home03-qualification
test ! -e "$fixture_root"
install -d -m 755 "$fixture_root" /etc/greentic /etc/greentic/admin /mnt/greentic/bundles
install -d -m 755 /mnt/greentic/bundles/iot-home03-simulator
install -d -m 755 /var/lib/iot-home03
for directory in state cache logs temp; do
    install -d -o 1000 -g 1000 -m 700 "/var/lib/iot-home03/$directory"
done
install -m 644 "$(dirname "$0")/simulator.py" "$fixture_root/simulator.py"
install -m 644 "$(dirname "$0")/Dockerfile" "$fixture_root/Dockerfile"
docker --host unix:///var/run/docker.sock pull ubuntu:24.04
docker --host unix:///var/run/docker.sock image inspect ubuntu:24.04 --format '{{index .RepoDigests 0}}' > "$fixture_root/base-image.txt"
docker --host unix:///var/run/docker.sock build --build-arg "BASE=$(cat "$fixture_root/base-image.txt")" -t iot-home03-sim:good "$fixture_root"
docker --host unix:///var/run/docker.sock image inspect iot-home03-sim:good --format '{{.Id}}' > "$fixture_root/good-image.txt"
printf 'FROM iot-home03-sim:good\nRUN touch /opt/force-unhealthy\n' > "$fixture_root/Dockerfile.bad"
docker --host unix:///var/run/docker.sock build -f "$fixture_root/Dockerfile.bad" -t iot-home03-sim:bad "$fixture_root"
docker --host unix:///var/run/docker.sock image inspect iot-home03-sim:bad --format '{{.Id}}' > "$fixture_root/bad-image.txt"
install -d -m 755 "$fixture_root/bundle-src"
printf '{"kind":"host-qualification-simulator","version":1}\n' > "$fixture_root/bundle-src/fixture.json"
mksquashfs "$fixture_root/bundle-src" "$fixture_root/simulator.squashfs" -noappend -all-root -quiet
chmod 644 "$fixture_root/simulator.squashfs"
umask 077
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=HOME03-qualification-CA -keyout "$fixture_root/ca.key" -out /etc/greentic/admin/ca.crt
openssl req -newkey rsa:2048 -nodes -subj /CN=localhost -keyout /etc/greentic/admin/server.key -out "$fixture_root/server.csr"
printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n' > "$fixture_root/server.ext"
openssl x509 -req -in "$fixture_root/server.csr" -CA /etc/greentic/admin/ca.crt -CAkey "$fixture_root/ca.key" -CAcreateserial -days 2 -extfile "$fixture_root/server.ext" -out /etc/greentic/admin/server.crt
openssl req -newkey rsa:2048 -nodes -subj /CN=host-health -keyout /etc/greentic/health-client.key -out "$fixture_root/client.csr"
printf 'extendedKeyUsage=clientAuth\n' > "$fixture_root/client.ext"
openssl x509 -req -in "$fixture_root/client.csr" -CA /etc/greentic/admin/ca.crt -CAkey "$fixture_root/ca.key" -CAcreateserial -days 2 -extfile "$fixture_root/client.ext" -out /etc/greentic/health-client.crt
chown 0:1000 /etc/greentic/admin/server.key
chmod 440 /etc/greentic/admin/server.key
chmod 644 /etc/greentic/admin/ca.crt /etc/greentic/admin/server.crt
printf 'Fixture artifacts staged. No workload has been started.\n'
