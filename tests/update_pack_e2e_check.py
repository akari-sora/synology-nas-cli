"""End-to-end check of the DSM Update-pack route of `nas upgrade`, through the real CLI.

Runs `cli.main([...])` with the real password backend: HTTPS with the
certificate pinned on first use, login, form calls and the streamed multipart
upload all go to a fake DSM on 127.0.0.1. The fake DSM checks what it
receives (the uploaded bytes, their MD5 and their pack header) and plays the
install: busy/idle status, PreCheck, start, reboot (SessionData down, then
ready) and the new firmware version.

Default (offline, in tests/run_offline.sh): a second local server stands in
for Synology's download API and CDN and serves crafted packs.
NAS_E2E_LIVE=1: Synology's real findDownloadInfo and CDN are used, and the
real DS716+ and DS916+ packs are downloaded (about 11 MB). No NAS is
contacted in either mode. Needs `openssl` for the test certificate.
"""
import ast
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import threading
import time as _time
import types
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer

LIVE = os.environ.get("NAS_E2E_LIVE", "") not in ("", "0")  # read before _env clears NAS_*

import _env  # noqa: E402

if not shutil.which("openssl"):
    print(f"update-pack e2e checks skipped: no openssl (python {sys.version.split()[0]})")
    sys.exit(0)

from nas import advisories, cli, upgrade  # noqa: E402

UNIQUE = "synology_braswell_716+"
OTHER = "synology_braswell_916+"
FW0 = "DSM 7.4.1-90080"
FW1 = "DSM 7.4.1-90080 Update 1"
PACK_RE = re.compile(rb"\{'archive_type'\s*:\s*'update_pack'.*?\}", re.S)


def crafted_pack(unique, magic, smallfixnum=1):
    header = ("{'archive_type': 'update_pack', 'platform': 'braswell', 'buildnum': '90080', "
              "'major': '7', 'minor': '4', 'productversion': '7.4.1', "
              f"'smallfixnum': {smallfixnum}, 'unique': '{unique}'}}")
    body = os.urandom(64 * 1024)  # stands in for the signed payload
    return magic + b"\x00" * 236 + header.encode("ascii") + b"\x00" * 1024 + body


# --- fake Synology download API + CDN (offline mode) -------------------------------

PACKS = {UNIQUE: crafted_pack(UNIQUE, b"\xb6\xad\xbe\xef"), OTHER: crafted_pack(OTHER, b"\xac\xad\xbe\xef")}


class CDN(BaseHTTPRequestHandler):
    def _pack(self):
        m = re.fullmatch(r"/update_pack/90080-1/(.+)\.pat", urllib.parse.urlsplit(self.path).path)
        return PACKS.get(urllib.parse.unquote(m.group(1))) if m else None

    def _reply(self, body, head_only=False, etag=None, ctype="application/octet-stream"):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if etag:
            self.send_header("ETag", f'"{etag}"')
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def do_HEAD(self):
        blob = self._pack()
        if blob is None:
            self.send_response(404)
            self.end_headers()
            return
        self._reply(blob, head_only=True, etag=hashlib.md5(blob).hexdigest())

    def do_GET(self):
        if self.path.startswith("/api/support/findDownloadInfo"):
            info = {"info": {"pubVers": [{"version": "7.4.1-90080"}], "system": {"detail": [{"items": [
                {"build_ver": "7.4.1", "build_num": "90080", "latest_nano": 1, "required_ver": "7.4",
                 "required_num": "90075", "files": [{"url": "https://example.invalid/DSM_DS716%2B_90080.pat"}]}]}]}}}
            self._reply(json.dumps(info).encode(), ctype="application/json")
            return
        blob = self._pack()
        if blob is None:
            self.send_response(404)
            self.end_headers()
            return
        self._reply(blob, etag=hashlib.md5(blob).hexdigest())

    def log_message(self, *a):
        pass


# --- fake DSM ------------------------------------------------------------------------

APIS = {
    "SYNO.API.Auth": {"path": "auth.cgi", "minVersion": 1, "maxVersion": 7},
    "SYNO.Core.System": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 3},
    "SYNO.Core.Upgrade": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 2},
    "SYNO.Core.Upgrade.Patch": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
    "SYNO.Core.Upgrade.PreCheck": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
}


class Dsm:
    def reset(self, fw, status="none"):
        self.fw = fw
        self.status = status
        self.uploads = []      # (md5, size, header dict or None)
        self.calls = []        # (api, method)
        self.down_polls = 0    # SessionData answers 503 this many times after start
        self.pending_fw = None
        self.logins = 0


DSM = Dsm()


class DsmHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(url.query))
        if url.path == "/webapi/query.cgi":
            return self._json({"success": True, "data": APIS})
        if q.get("api") == "SYNO.Core.Desktop.SessionData":
            if DSM.down_polls > 0:
                DSM.down_polls -= 1
                if DSM.down_polls == 0 and DSM.pending_fw:
                    DSM.fw, DSM.pending_fw = DSM.pending_fw, None  # back from the reboot on the new version
                return self._json({"error": "rebooting"}, code=503)
            body = b'SYNO.SDS.Session = {"dsm_upgrade_all_done": true, "hostname": "fake"};'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        return self._json({"success": False, "error": {"code": 102}})

    def do_POST(self):
        url = urllib.parse.urlsplit(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n)
        ctype = self.headers.get("Content-Type") or ""
        if ctype.startswith("multipart/form-data"):
            return self._upload(dict(urllib.parse.parse_qsl(url.query)), ctype, raw)
        f = dict(urllib.parse.parse_qsl(raw.decode()))
        api, method = f.get("api"), f.get("method")
        DSM.calls.append((api, method))
        if api == "SYNO.API.Auth":
            if method == "login":
                assert f.get("account") == "e2e" and f.get("passwd") == "e2e-pass", "wrong credentials sent"
                DSM.logins += 1
                return self._json({"success": True, "data": {"sid": f"sid{DSM.logins}", "synotoken": "tok"}})
            return self._json({"success": True})
        assert f.get("_sid", "").startswith("sid"), (api, method, "no session")
        if (api, method) == ("SYNO.Core.System", "info"):
            return self._json({"success": True, "data": {"model": "DS716+", "firmware_ver": DSM.fw}})
        if (api, method) == ("SYNO.Core.Upgrade", "status"):
            return self._json({"success": True, "data": {"status": DSM.status}})
        if (api, method) == ("SYNO.Core.Upgrade.PreCheck", "start"):
            assert f.get("type") == "patch", f
            return self._json({"success": True})
        if (api, method) == ("SYNO.Core.Upgrade", "start"):
            assert DSM.uploads, "start without an upload"
            assert f.get("type") == "patch", f
            hdr = DSM.uploads[-1][2]
            DSM.pending_fw = f"DSM {hdr['productversion']}-{hdr['buildnum']} Update {hdr['smallfixnum']}"
            DSM.down_polls = 3
            return self._json({"success": True, "data": {}})
        if (api, method) == ("SYNO.Core.Upgrade.Patch", "clean"):
            return self._json({"success": True})
        return self._json({"success": False, "error": {"code": 103}})

    def _upload(self, q, ctype, raw):
        DSM.calls.append((q.get("api"), q.get("method")))
        assert (q.get("api"), q.get("method")) == ("SYNO.Core.Upgrade.Patch", "upload"), q
        assert q.get("_sid", "").startswith("sid"), "upload without a session"
        boundary = ctype.split("boundary=", 1)[1].encode()
        parts = raw.split(b"--" + boundary)
        fields, blob = {}, None
        for part in parts:
            if b"\r\n\r\n" not in part:
                continue
            head, _, body = part.partition(b"\r\n\r\n")
            body = body[:-2] if body.endswith(b"\r\n") else body
            name = re.search(rb'name="([^"]+)"', head).group(1).decode()
            if name == "file":
                assert blob is None, "two files"
                blob = body
            else:
                assert blob is None, f"field {name} after the file (DSM reads fields first)"
                fields[name] = body.decode()
        assert fields.get("target") == "active" and blob, fields
        m = PACK_RE.search(blob[:8192])
        header = ast.literal_eval(m.group(0).decode("ascii")) if m else None
        DSM.uploads.append((hashlib.md5(blob).hexdigest(), len(blob), header))
        build = int(header["buildnum"]) if header else 90080
        return self._json({"success": True, "data": {"buildnumber": build, "upgradetype": "nano", "reboot": True}})

    def log_message(self, *a):
        pass


def make_cert():
    crt, key = os.path.join(_env.TMP, "e2e.crt"), os.path.join(_env.TMP, "e2e.key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj",
                    "/CN=nas-e2e", "-keyout", key, "-out", crt], check=True, capture_output=True)
    return crt, key


def serve_dsm():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), DsmHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(*make_cert())
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


dsm = serve_dsm()
origin = f"https://127.0.0.1:{dsm.server_address[1]}"
cache = os.path.join(_env.TMP, "pat")
_env.use_config({
    "origins": [origin],
    "dsm_unique": UNIQUE,
    "tls": {"known_certs_file": os.path.join(_env.TMP, "e2e-certs.json")},
    "session": {"cache_file": os.path.join(_env.TMP, "e2e-session.json"),
                "device_token_file": os.path.join(_env.TMP, "e2e-device.json")},
    "credentials": {"source": "env", "op_token_file": os.path.join(_env.TMP, "no-token")},
    "upgrade": {"lang": "enu", "cache_dir": cache},
})
os.environ["NAS_USER"] = "e2e"
os.environ["NAS_PASSWORD"] = "e2e-pass"
os.environ["NAS_CONFIG"] = os.path.join(_env.TMP, "config.json")

if not LIVE:
    cdn = HTTPServer(("127.0.0.1", 0), CDN)
    threading.Thread(target=cdn.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{cdn.server_address[1]}"
    upgrade.DOWNLOAD_API = base + "/api/support/findDownloadInfo"
    upgrade.UPDATE_PACK_URL = base + "/update_pack"
    urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))

# a fake clock for the reboot wait only (15 s polls, 60 s version checks)
_clock = [_time.time()]
upgrade.time = types.SimpleNamespace(time=lambda: _clock[0], strftime=_time.strftime,
                                     sleep=lambda s: _clock.__setitem__(0, _clock[0] + s))


def nas(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = cli.main(["--json", *argv])
    text = out.getvalue()
    data = json.loads(text) if rc == 0 and text.strip() else None
    return rc, data, err.getvalue()


def pack_path(unique):
    return os.path.join(cache, "90080-1", unique + ".pat")


# 1. dry run on the vulnerable build: the pack is found, nothing is fetched or staged
DSM.reset(FW0)
assert advisories.dsm_verdict(FW0)["advisories"]["sa_26_19"]["status"] == "vulnerable"
rc, data, err = nas("upgrade", "--dry-run")
assert rc == 0 and data["action"] == "dry-run", (rc, data, err)
assert data["pack"]["update"] == 1 and data["pack"]["needed"] == 1 and data["pack"]["status"] == 200, data
assert data["pack"]["url"].endswith("/90080-1/synology_braswell_716%2B.pat"), data
assert not DSM.uploads and not os.path.exists(pack_path(UNIQUE)), DSM.uploads

# 2. without --install-update: downloaded, checksum and header verified, nothing uploaded
rc, data, err = nas("upgrade")
assert rc == 0 and data["action"] == "downloaded", (rc, data, err)
assert data["target"]["update_pack"] and data["target"]["file"] == pack_path(UNIQUE), data
local_md5 = hashlib.md5(open(pack_path(UNIQUE), "rb").read()).hexdigest()
if LIVE:
    _s, live_size, live_etag = upgrade._head(data["pack"]["url"])
    assert live_etag == local_md5 and live_size == os.path.getsize(pack_path(UNIQUE)), (live_etag, local_md5)
assert not DSM.uploads, DSM.uploads

# 3. DSM busy with its own update: refused before anything is staged
DSM.reset(FW0, status="upgrading")
rc, data, err = nas("upgrade", "--install-update", "--yes")
assert rc != 0 and "busy" in err, (rc, err)
assert not DSM.uploads and ("SYNO.Core.Upgrade", "start") not in DSM.calls, DSM.calls

# 4. the install: upload, PreCheck, start, reboot, back on Update 1 -> both advisories patched
DSM.reset(FW0)
rc, data, err = nas("upgrade", "--install-update", "--yes")
assert rc == 0 and data["action"] == "installed", (rc, data, err)
assert data["after"] == FW1 and DSM.fw == FW1, (data, DSM.fw)
assert len(DSM.uploads) == 1, DSM.uploads
up_md5, up_size, up_header = DSM.uploads[0]
assert up_md5 == local_md5 and up_size == os.path.getsize(pack_path(UNIQUE)), "uploaded bytes differ"
assert up_header["unique"] == UNIQUE and up_header["smallfixnum"] == 1, up_header
assert ("SYNO.Core.Upgrade.Patch", "clean") not in DSM.calls, DSM.calls
assert "DSM down" in err and DSM.logins >= 2, err  # went down, logged in again afterwards
after = advisories.dsm_verdict(data["after"])
assert after["status"] == "patched", after
assert after["advisories"]["sa_26_19"]["status"] == "patched", after
assert after["advisories"]["sa_26_13"]["status"] == "patched", after

# 5. already on Update 1: nothing to do, and the same pack by hand is refused
DSM.reset(FW1)
rc, data, err = nas("upgrade", "--dry-run")
assert rc == 0 and data["action"] == "none", (rc, data, err)
rc, data, err = nas("upgrade", "--pat", pack_path(UNIQUE), "--yes")
assert rc != 0 and "already on Update 1" in err, (rc, err)
assert not DSM.uploads, DSM.uploads

# 6. another model's pack (same size class, other magic on the real 916+ file): refused by its header
if LIVE:
    other = upgrade._download(upgrade._update_pack_url(OTHER, 90080, 1), os.path.join(_env.TMP, "other"),
                              subdir="90080-1")
else:
    other = os.path.join(_env.TMP, OTHER + ".pat")
    with open(other, "wb") as f:
        f.write(PACKS[OTHER])
DSM.reset(FW0)
rc, data, err = nas("upgrade", "--pat", other, "--yes")
assert rc != 0 and "pack is for synology_braswell_916+" in err, (rc, err)
assert not DSM.uploads, DSM.uploads

# 7. the right pack by hand on Update 0 installs the same way
DSM.reset(FW0)
rc, data, err = nas("upgrade", "--pat", pack_path(UNIQUE), "--yes")
assert rc == 0 and data["action"] == "installed" and data["after"] == FW1, (rc, data, err)
assert DSM.uploads[0][0] == local_md5

dsm.shutdown()
mode = "live Synology download API + CDN" if LIVE else "local fake CDN"
print(f"update-pack e2e checks ok ({mode}; python {sys.version.split()[0]})")
