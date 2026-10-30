"""Offline checks of `nas setup` and `nas doctor`: missing-field JSON without hanging, config write and merge,
one real login against a fake DSM over HTTPS (certificate pinned), no retry after 400, 2FA via --otp-code and
--trust-device, and doctor's checks in canned states."""
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import _env

BIN = os.path.join(_env.ROOT, "bin", "nas")
T = tempfile.mkdtemp(prefix="nas-onboard-")


def run(args, env=None, stdin=subprocess.DEVNULL, timeout=40):
    e = {k: v for k, v in os.environ.items() if not k.startswith("NAS_") and k != "OP_SERVICE_ACCOUNT_TOKEN"}
    e.update(HOME=T, NAS_CONFIG=os.path.join(T, "config.json"))
    e.update(env or {})
    p = subprocess.run([sys.executable, BIN] + args, env=e, stdin=stdin, capture_output=True, text=True, timeout=timeout)
    try:
        data = json.loads(p.stdout) if "--json" in args else None
    except ValueError:
        raise AssertionError(f"not JSON: {p.stdout!r} {p.stderr!r}")
    return p.returncode, data, p.stdout, p.stderr


# --- missing information: exit 3 with questions, never a wait -----------------------------------------------
t0 = time.time()
rc, d, out, err = run(["setup", "--json", "--no-input"])
assert rc == 3 and {m["field"] for m in d["missing"]} == {"origin", "password_source", "user"}, (rc, d, err)
assert all(set(m) == {"field", "why", "ask_user"} and m["ask_user"] for m in d["missing"])
assert not os.path.exists(os.path.join(T, "config.json")), "nothing written while information is missing"
# stdin is an open pipe that never sends anything: still no hang
p = subprocess.Popen([sys.executable, BIN, "setup", "--json", "--origin", "https://192.0.2.10:5001", "--user", "ops",
                      "--save-to-keychain", "--password-stdin"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE, text=True,
                     env=dict(os.environ, HOME=T, NAS_CONFIG=os.path.join(T, "config.json")))
try:
    out, err = p.communicate(timeout=25)
finally:
    p.kill()
assert p.returncode == 3 and json.loads(out)["missing"][0]["field"] == "password", (p.returncode, out, err)
assert time.time() - t0 < 30
rc, d, _, _ = run(["setup", "--json", "--origin", "https://192.0.2.10:5001", "--password-source", "env"])
assert rc == 3 and [m["field"] for m in d["missing"]] == ["user", "password"], d  # NAS_PASSWORD not set either
rc, _, _, err = run(["setup", "--password-source", "magic"])
assert rc == 1 and "--password-source 'magic'" in err, err

if not shutil.which("openssl"):
    print(f"onboard checks ok, fake-DSM part skipped: no openssl (python {sys.version.split()[0]})")
    sys.exit(0)

# --- a fake DSM over HTTPS -----------------------------------------------------------------------------------
crt, key = os.path.join(T, "c.crt"), os.path.join(T, "c.key")
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=nas-test",
                "-keyout", key, "-out", crt], check=True, capture_output=True)
STATE = {"password": "pw", "otp": False, "logins": [], "logouts": 0, "valid": set(), "2fa": False}
INFO = {k: {"path": "entry.cgi", "minVersion": 1, "maxVersion": v, "requestFormat": "JSON"}
        for k, v in (("SYNO.API.Auth", 7), ("SYNO.Core.System", 3), ("SYNO.Core.User", 1))}


class DSM(BaseHTTPRequestHandler):
    def _send(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        if q.get("api") == ["SYNO.API.Info"]:
            return self._send({"success": True, "data": INFO})
        self._send({"success": False, "error": {"code": 102}})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        f = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(n).decode()).items()}
        if f.get("method") == "login":
            STATE["logins"].append(f)
            if f.get("passwd") != STATE["password"]:
                return self._send({"success": False, "error": {"code": 400}})
            if STATE["otp"] and f.get("otp_code") != "246810" and f.get("device_id") != "DEV1":
                return self._send({"success": False, "error": {"code": 403}})
            sid = "sid%d" % len(STATE["logins"])
            STATE["valid"].add(sid)
            data = {"sid": sid, "synotoken": "tok"}
            if f.get("enable_device_token") == "yes":
                data["did"] = "DEV1"
            return self._send({"success": True, "data": data})
        if f.get("method") == "logout":
            STATE["logouts"] += 1
            STATE["valid"].discard(f.get("_sid"))
            return self._send({"success": True})
        if f.get("_sid") not in STATE["valid"]:
            return self._send({"success": False, "error": {"code": 119}})
        if f.get("api") == "SYNO.Core.System":
            return self._send({"success": True, "data": {"model": "DS000", "firmware_ver": "DSM 7.4.1-90080 Update 1"}})
        if f.get("api") == "SYNO.Core.User":
            return self._send({"success": True, "data": {"users": [{"name": "ops", "2fa_status": STATE["2fa"]}]}})
        self._send({"success": False, "error": {"code": 102}})

    def log_message(self, *a):
        pass


srv = HTTPServer(("127.0.0.1", 0), DSM)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(crt, key)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
threading.Thread(target=srv.serve_forever, daemon=True).start()
ORIGIN = f"https://127.0.0.1:{srv.server_port}"
CFG = os.path.join(T, "config.json")
json.dump({"name": "keep-me", "deploy": {"stage_dir": "/files/.nas-cli-deploy"}}, open(CFG, "w"))

# setup: writes (merging), signs in once, pins the certificate, logs out
rc, d, _, err = run(["setup", "--json", "--origin", ORIGIN, "--user", "ops", "--password-source", "env",
                     "--allowed-network", "192.0.2.0/24", "--allowed-network", "100.64.0.0/10"], env={"NAS_PASSWORD": "pw"})
assert rc == 0 and d["login"] == "ok" and d["account"] == "ops" and d["dsm"] == "DSM 7.4.1-90080 Update 1", (rc, d, err)
assert len(STATE["logins"]) == 1 and STATE["logouts"] == 1 and d["tls"]["mode"] == "pin" and len(d["tls"]["sha256"]) == 64
written = json.load(open(CFG))
assert written["name"] == "keep-me" and written["origins"] == [ORIGIN] and written["deploy"]["stage_dir"]
assert written["allowed_networks"] == ["192.0.2.0/24", "100.64.0.0/10"]
assert written["credentials"] == {"username": "ops", "source": "env"}, written["credentials"]
assert oct(os.stat(CFG).st_mode & 0o777) == "0o600"
assert "NAS_PASSWORD" not in open(CFG).read() and "pw" not in json.dumps(written)

# doctor on a working setup: everything ok, exit 0
rc, d, out, _ = run(["doctor", "--json"], env={"NAS_PASSWORD": "pw"})
st = {c["name"]: c["status"] for c in d["checks"]}
assert rc == 0 and d["ok"] and st == {"config": "ok", "credentials": "ok", "origin": "ok", "tls": "ok", "login": "ok",
                                      "dsm_version": "ok", "two_factor": "ok", "capabilities": "ok", "clock": "ok"}, d
assert all(set(c) == {"name", "status", "detail", "next_step"} for c in d["checks"])
assert "pinned" in next(c for c in d["checks"] if c["name"] == "tls")["detail"]

# wrong password: one attempt, exit 4, said so, not retried
n = len(STATE["logins"])
rc, d, _, _ = run(["setup", "--json"], env={"NAS_PASSWORD": "bad"})
assert rc == 4 and len(STATE["logins"]) == n + 1 and "failed" in d["login"], (rc, d)
rc, _, out, _ = run(["setup"], env={"NAS_PASSWORD": "bad"})
assert rc == 4 and "Not retried" in out and "AutoBlock" in out and len(STATE["logins"]) == n + 2
rc, d, _, _ = run(["doctor", "--json"], env={"NAS_PASSWORD": "bad"})
login = next(c for c in d["checks"] if c["name"] == "login")
assert rc == 1 and login["status"] == "fail" and "AutoBlock" in login["next_step"] and len(STATE["logins"]) == n + 3

# 2-step verification: setup reports the code as missing (exit 3); --otp-code + --trust-device finish it
STATE["otp"], STATE["2fa"] = True, True
rc, d, _, _ = run(["setup", "--json"], env={"NAS_PASSWORD": "pw"})
assert rc == 3 and d["missing"][0]["field"] == "otp" and "2-step" in d["missing"][0]["ask_user"], d
rc, d, _, _ = run(["doctor", "--json"], env={"NAS_PASSWORD": "pw"})
two = next(c for c in d["checks"] if c["name"] == "two_factor")
assert rc == 1 and two["status"] == "fail" and "--otp-code" in two["next_step"], d
rc, d, _, err = run(["setup", "--json", "--otp-code", "246810", "--trust-device"], env={"NAS_PASSWORD": "pw"})
assert rc == 0 and d["login"] == "ok", (rc, d, err)
assert json.load(open(os.path.join(T, ".config/synology-nas-cli/device-token.json"))) == {"devices": {"ops": "DEV1"}}
rc, d, _, _ = run(["doctor", "--json"], env={"NAS_PASSWORD": "pw"})  # the trusted device now skips the code
two = next(c for c in d["checks"] if c["name"] == "two_factor")
assert rc == 0 and "trusted-device token stored" in two["detail"] and "on" in two["detail"], d

# unreachable origin: doctor says so and does not try to sign in
dead = socket.socket()
dead.bind(("127.0.0.1", 0))
port = dead.getsockname()[1]
dead.close()
n = len(STATE["logins"])
rc, d, _, _ = run(["doctor", "--json"], env={"NAS_PASSWORD": "pw", "NAS_ORIGINS": f"https://127.0.0.1:{port}"})
st = {c["name"]: c["status"] for c in d["checks"]}
assert rc == 1 and st["origin"] == "fail" and st["login"] == "skip" and len(STATE["logins"]) == n, d
# a broken config file: doctor still answers
open(CFG, "w").write("{broken")
rc, d, _, _ = run(["doctor", "--json"])
assert rc == 1 and d["checks"][0]["name"] == "config" and d["checks"][0]["status"] == "fail" and "not valid JSON" in d["checks"][0]["detail"]
srv.shutdown()
print(f"onboard checks ok (python {sys.version.split()[0]})")
