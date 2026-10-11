"""Service-only host qualification simulator; never controls IoT hardware."""
import http.server
import json
import os
from pathlib import Path
import ssl

state = Path(os.environ["GREENTIC_STATE_DIR"])
counter = state / "boot-count"
boots = int(counter.read_text()) + 1 if counter.exists() else 1
temporary = state / "boot-count.new"
with temporary.open("w") as out:
    out.write(str(boots))
    out.flush()
    os.fsync(out.fileno())
temporary.replace(counter)
directory = os.open(state, os.O_RDONLY)
os.fsync(directory)
os.close(directory)

source = os.environ["GREENTIC_BUNDLE_SOURCE"].removeprefix("file://")
with open(source, "rb") as bundle:
    if bundle.read(4) != b"hsqs":
        raise RuntimeError("qualification requires a real staged squashfs fixture")


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        healthy = not Path("/opt/force-unhealthy").exists()
        self.send_response(200 if healthy else 503)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"healthy": healthy, "boots": boots}).encode())


bind, port = os.environ["GREENTIC_ADMIN_LISTEN"].rsplit(":", 1)
server = http.server.ThreadingHTTPServer((bind, int(port)), Handler)
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain(os.environ["GREENTIC_ADMIN_CERT_FILE"], os.environ["GREENTIC_ADMIN_KEY_FILE"])
tls.load_verify_locations(os.environ["GREENTIC_ADMIN_CA_FILE"])
tls.verify_mode = ssl.CERT_REQUIRED
server.socket = tls.wrap_socket(server.socket, server_side=True)
server.serve_forever()
