"""Offline check of the DSM HTTPS opener: proxies are never used, a self-signed certificate is trusted on first
use, a different certificate is refused, `nas trust --reset` forgets it. Needs the `openssl` binary to make test
certificates; skipped without it."""
import json
import os
import shutil
import ssl
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import _env

from nas import cli, config
from nas.backends import PasswordBackend, PinMismatch, check_pin, load_pins, make_opener
from nas.errors import NasError

# unit: first use records, the same certificate passes, another one is refused
pins = os.path.join(_env.TMP, "pins-unit.json")
check_pin(pins, "https://192.0.2.10:5001", b"cert-A")
check_pin(pins, "https://192.0.2.10:5001", b"cert-A")
try:
    check_pin(pins, "https://192.0.2.10:5001", b"cert-B")
    raise AssertionError("changed certificate accepted")
except PinMismatch as e:
    assert "nas trust --reset https://192.0.2.10:5001" in str(e)
assert oct(os.stat(pins).st_mode & 0o777) == "0o600"

if not shutil.which("openssl"):
    print(f"tls checks ok, server part skipped: no openssl (python {sys.version.split()[0]})")
    sys.exit(0)


def make_cert(name):
    crt, key = os.path.join(_env.TMP, name + ".crt"), os.path.join(_env.TMP, name + ".key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=nas-test",
                    "-keyout", key, "-out", crt], check=True, capture_output=True)
    return crt, key


BLOB = bytes(range(256)) * 4096  # 1 MiB of binary


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if "SYNO.FileStation.Download" in self.path:
            missing = "nope" in self.path
            body = b'{"error":{"code":408},"success":false}' if missing else BLOB
            self.send_response(200)
            self.send_header("Content-Type", "application/json" if missing else "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = json.dumps({"success": True, "data": {"ok": 1}}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def serve(cert):
    srv = HTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(*cert)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


pins = os.path.join(_env.TMP, "known-certs.json")
_env.use_config({"tls": {"known_certs_file": pins}})
os.environ["HTTPS_PROXY"] = os.environ["https_proxy"] = "http://127.0.0.1:9"  # nothing listens there
os.environ["ALL_PROXY"] = "http://127.0.0.1:9"
srv = serve(make_cert("a"))
origin = f"https://127.0.0.1:{srv.server_port}"
b = PasswordBackend([origin], cfg=config.get(), use_cache=False)
assert b._send(__import__("urllib.request").request.Request(origin + "/x"), 5)["success"], "direct, no proxy"
assert list(load_pins(pins)) == [origin]
assert b._send(__import__("urllib.request").request.Request(origin + "/x"), 5)["success"], "same certificate"
srv.shutdown()
srv.server_close()

srv2 = serve(make_cert("b"))  # another certificate on the same origin
origin2 = f"https://127.0.0.1:{srv2.server_port}"
pins_data = load_pins(pins)
pins_data[origin2] = pins_data.pop(origin)  # pretend the first certificate belonged to this origin
json.dump(pins_data, open(pins, "w"))
b2 = PasswordBackend([origin2], cfg=config.get(), use_cache=False)
try:
    b2._send(__import__("urllib.request").request.Request(origin2 + "/x"), 5)
    raise AssertionError("changed certificate accepted")
except NasError as e:
    assert "changed" in str(e) and "nas trust --reset" in str(e), e
assert cli.main(["trust", "--reset", origin2]) == 0 and origin2 not in load_pins(pins)
assert b2._send(__import__("urllib.request").request.Request(origin2 + "/x"), 5)["success"], "trusted again after reset"
# binary File Station download (incident rescue pulls captures with it): exact bytes, mode 600, no overwrite
b2._sid = "sid"
dl = os.path.join(_env.TMP, "dl.bin")
assert b2.download_to("/share/map-1000-2000.bin", dl) == len(BLOB) and open(dl, "rb").read() == BLOB
assert oct(os.stat(dl).st_mode & 0o777) == "0o600"
for path, target in (("/share/map.bin", dl), ("/share/nope.bin", dl + "2")):
    try:
        b2.download_to(path, target)
        raise AssertionError("download overwrote a file or accepted an error answer")
    except (FileExistsError, NasError):
        pass
assert not os.path.exists(dl + "2")
# tls.verify true: the system CAs decide, and a self-signed certificate fails
_env.use_config({"tls": {"verify": True, "known_certs_file": pins}})
try:
    make_opener(config.get()).open(origin2 + "/x", timeout=5)
    raise AssertionError("self-signed certificate accepted with tls.verify")
except Exception as e:
    assert "CERTIFICATE_VERIFY_FAILED" in str(e) or "certificate verify failed" in str(e), e
srv2.shutdown()
print(f"tls checks ok (python {sys.version.split()[0]})")
