"""Offline checks of `nas incident` (audit verdicts) and `nas incident fix` (plan, order, dry run,
apply + read-back, lockout refusal) against a fake NAS that keeps state (tests/fakenas.py)."""
import json
import sys
import types

import _env

from nas import config, incident
from nas.commands import is_read_method
from nas.errors import NasError
from fakenas import FakeNas, FakeSession, args, err, ok, status

_env.use_config({})
incident.client_address = lambda origin: ("192.0.2.50", "192.0.2.10")  # LAN client, LAN origin
incident.fresh_login_error = lambda s: None
incident.get_proxies = lambda: {}

# --- audit -----------------------------------------------------------------------------------------
nas = FakeNas()
lines, data, rc = incident.audit(FakeSession(nas), args())
got = status(data["items"])
want = {"dsm_version": "FAIL", "sa_26_14_packages": "FAIL", "firewall": "FAIL", "quickconnect": "WARN",
        "router_port_forwarding": "WARN", "public_ports": "SKIP", "external_signins": "FAIL", "failed_signins": "WARN",
        "autoblock": "WARN", "smb_min_protocol": "FAIL", "admin_account": "WARN",
        "snapshot_schedule:photos": "PASS", "snapshot_worm:photos": "FAIL",
        "snapshot_schedule:docs": "WARN", "snapshot_worm:docs": "PASS",
        "snapshot_schedule:media": "WARN", "snapshot_worm:media": "PASS", "ransomware_files": "SKIP",
        "exploit_attempts": "PASS", "exploit_attempts_logs": "SKIP", "ioc_cron": "SKIP", "ioc_binaries": "SKIP",
        "ioc_users": "SKIP", "ioc_ssh_keys": "SKIP", "ioc_processes": "SKIP"}
assert got == want, {k: (got.get(k), v) for k, v in want.items() if got.get(k) != v}
assert rc == 1 and data["summary"]["FAIL"] == 6
assert all(is_read_method(m) for _, m in nas.sent), [m for _, m in nas.sent if not is_read_method(m)]
ext = next(i for i in data["items"] if i["id"] == "external_signins")
assert "ops from 1.2.3.4 via password x1" in ext["detail"] and "192.0.2.50" not in ext["detail"], ext
fs = next(i for i in data["items"] if i["id"] == "failed_signins")
assert "25 failed" in fs["detail"] and "latest 2026/10/30 11:24:00" in fs["detail"], fs
# QuickConnect off but its port-forwarding setting on: PASS (the fix still turns the setting off)
qn = FakeNas()
qn.st["qc"] = False
qi = next(i for i in incident.audit(FakeSession(qn), args())[1]["items"] if i["id"] == "quickconnect")
assert qi["status"] == "PASS" and "still on" in qi["detail"], qi
assert any("-> nas incident fix --only firewall" in l for l in lines), lines
assert lines[-1].startswith("Summary: ")
# a patched, closed box passes; WORM unsupported but off passes
pat = FakeNas()
pat.st.update(fw_on=True, qc=False, qc_upnp=False, ab=True, smb_min=1, admin="now", php="stop", pf=[],
              worm={"photos": False, "docs": False}, sched={"photos": (True, 5), "docs": (True, 6), "media": (True, 7)})
pat.st["profile"] = {"name": "default", "global": {"policy": "none", "rules": []}, "eth0": {"policy": "drop", "rules": []},
                     "pppoe": {"policy": "drop", "rules": []}}
orig = pat.handle
pat.handle = lambda a, m, p: (ok({"firmware_ver": "DSM 7.4.1-90080 Update 1", "time": "2026-10-30 12:00:00"})
                              if (a, m) == ("SYNO.Core.System", "info") else
                              ok({"items": [], "total": 0}) if (a, m) == ("SYNO.Core.SyslogClient.Log", "list")
                              else orig(a, m, p))
got = status(incident.audit(FakeSession(pat), args())[1]["items"])
assert got["dsm_version"] == "PASS" and got["firewall"] == "PASS" and got["smb_min_protocol"] == "PASS", got
assert got["snapshot_worm:photos"] == "PASS" and got["admin_account"] == "PASS", got
# --probe on the local backend is a SKIP with the reason
it = next(i for i in incident.audit(FakeSession(FakeNas(), "local"), args(probe=True))[1]["items"] if i["id"] == "public_ports")
assert it["status"] == "SKIP" and "local" in it["detail"], it

# --- fix: plan and order ----------------------------------------------------------------------------
nas = FakeNas()
s = FakeSession(nas)
f = incident.gather(s, args())
changes = incident.plan(s, f, args(action="fix"))
order = [c["fix"] for c in changes]
assert order == ["snapshot_worm", "snapshots", "packages", "smb_min_protocol", "quickconnect",
                 "router_port_forwarding", "autoblock", "admin_account", "firewall"], order
# snapshot fixes wait for a clean ransom scan (or the explicit flag): starting snapshots applies retention
for c in changes[:2]:
    assert c["refused"] and "--i-know-snapshots-may-rotate" in c["refused"], c
assert all(not c["refused"] for c in changes[2:]), [c for c in changes[2:] if c["refused"]]
f_clean = dict(f, scan=({"finished": True, "root_hits": [], "search_hits": [], "shares": ["photos"]}, None))
assert not any(c["refused"] for c in incident.plan(s, f_clean, args(only="snapshot_worm,snapshots")))
f_hits = dict(f, scan=({"finished": True, "root_hits": ["/docs/read-me3.txt"], "search_hits": [], "shares": []}, None))
assert all(c["refused"] for c in incident.plan(s, f_hits, args(only="snapshot_worm,snapshots")))
changes = incident.plan(s, f, args(action="fix", i_know_snapshots_may_rotate=True))
# only shares without any schedule get one; a disabled existing schedule (media) is left alone
assert [c["target"] for c in changes if c["fix"] == "snapshots"] == ["docs"]
docs = next(c for c in changes if c["target"] == "docs")
assert docs["calls"][0]["params"]["task_id"] == -1 and docs["calls"][1]["params"]["retainDay"] == 14
assert docs["calls"][1]["params"]["policyType"] == 64 and "name" in docs["calls"][1]["params"]
# a share that already has a retention policy keeps it
orig_handle = nas.handle
nas.handle = lambda a, m, p: (ok({"name": "docs", "policyType": 2, "retainDay": 30})
                              if (a, m) == ("SYNO.DisasterRecovery.Retention", "get") else orig_handle(a, m, p))
kept = next(c for c in incident.plan(s, f, args(only="snapshots", i_know_snapshots_may_rotate=True)))
assert len(kept["calls"]) == 1 and "retention policy (type 2) is kept" in kept["note"], kept
nas.handle = orig_handle
# firewall: allow rules on the LAN interface; with allowed_networks empty only this client's /32 as DSM logged it
fw = changes[-1]
prof = fw["calls"][0]["params"]["profile"]
assert prof["eth0"]["policy"] == "drop" and prof["pppoe"] == {"policy": "drop", "rules": []}, prof
assert [r["source_ip"] for r in prof["eth0"]["rules"]] == ["192.0.2.50/255.255.255.255"], prof["eth0"]
assert prof["global"]["rules"] == [], "nothing added to global when a LAN interface exists"
assert "192.0.2.50/32 added" in fw["note"] and "allowed_networks is empty" in fw["note"] and "removed rules" in fw["note"]
ab = next(c for c in changes if c["fix"] == "autoblock")
assert ab["calls"][0]["params"]["enable"] is True and ab["calls"][1]["params"]["ip"] == ["192.0.2.50"], ab["calls"]
# configured networks: added on the LAN interface, CGNAT note because the NAS dials PPPoE; loopback only when opted in
_env.use_config({"allowed_networks": ["192.0.2.0/24", "100.64.0.0/10", "fd7a:115c:a1e0::/48"],
                 "incident": {"autoblock_allow_loopback": True}})
c = incident.plan_firewall(s, f)
srcs = [r["source_ip"] for r in c["calls"][0]["params"]["profile"]["eth0"]["rules"]]
assert srcs == ["192.0.2.0/255.255.255.0", "100.64.0.0/255.192.0.0"], srcs
assert "CGNAT" in c["note"] and "fd7a:115c:a1e0::/48" in c["note"] and "added" not in c["note"], c["note"]
ab = next(x for x in incident.plan(s, f, args(only="autoblock")))
assert ab["calls"][1]["params"]["ip"] == ["127.0.0.1", "192.0.2.0/255.255.255.0", "100.64.0.0/255.192.0.0"], ab["calls"]
# an allow entry stored as a subnet is found through the list call (get alone would miss it)
n2 = FakeNas()
n2.st["ab_allow"] = {"192.0.2.0/255.255.255.0"}
s2 = FakeSession(n2)
abp = next(x for x in incident.plan(s2, incident.gather(s2, args()), args(only="autoblock")))
assert abp["calls"][1]["params"]["ip"] == ["127.0.0.1", "100.64.0.0/255.192.0.0"], abp["calls"]
n2.st["ab_list_broken"] = True  # list unreadable: get alone decides (it only knows single addresses)
abp = next(x for x in incident.plan(s2, incident.gather(s2, args()), args(only="autoblock")))
assert "192.0.2.0/255.255.255.0" in abp["calls"][1]["params"]["ip"] and not abp["refused"]
_env.use_config({})
assert incident.as_nas_api(incident.call("SYNO.Core.Security.Firewall.Profile.Apply", "status", 1, {"task_id": "x"})) \
    == "nas api SYNO.Core.Security.Firewall.Profile.Apply status --version 1 task_id=x"
assert "nas api SYNO.Core.FileServ.SMB set --version 3" in incident.as_nas_api(
    next(c for c in changes if c["fix"] == "smb_min_protocol")["calls"][0])
# --only / --skip / --share and unknown names
assert [c["fix"] for c in incident.plan(s, f, args(only="smb_min_protocol,firewall"))] == ["smb_min_protocol", "firewall"]
assert "firewall" not in [c["fix"] for c in incident.plan(s, f, args(skip="firewall"))]
assert [c["target"] for c in incident.plan(s, f, args(only="snapshots", share=["media"]))] == []
try:
    incident.plan(s, f, args(only="firewal"))
    raise AssertionError("unknown fix name accepted")
except NasError as e:
    assert "unknown fix name" in str(e)

# --- admin: needs another enabled administrator and a known account ----------------------------------
for st, why in [({"admins_resp": ok({"users": [{"name": "admin"}]})}, "admin is the only enabled administrator"),
                ({"admins_resp": err(105)}, "the administrators group could not be read")]:
    n2 = FakeNas()
    n2.st.update(st)
    s2 = FakeSession(n2)
    f2 = incident.gather(s2, args())
    c = next(x for x in incident.plan(s2, f2, args(only="admin_account")))
    assert c["refused"] and why in c["refused"] and "(override: --force-admin)" in c["refused"], c
    for flags in ({"force_admin": True}, {"force": True}):  # overridden: planned, the check result kept in the note
        c = next(x for x in incident.plan(s2, f2, args(only="admin_account", **flags)))
        assert not c["refused"] and why in c["note"] and "--force-admin" in c["note"], c
s2 = FakeSession(FakeNas())
s2.backend.account = None  # a pasted NAS_SID session: the account comes from Initdata
c = next(x for x in incident.plan(s2, incident.gather(s2, args()), args(only="admin_account")))
assert not c["refused"] and s2.backend.account == "ops", c

# --- lockout refusal -----------------------------------------------------------------------------
cases = [
    (lambda: setattr(incident, "client_address", lambda o: ("192.0.2.50", "8.8.8.8")), "public address"),
    (lambda: setattr(incident, "client_address", lambda o: ("127.0.0.1", "127.0.0.1")), "loopback address"),
    (lambda: setattr(incident, "client_address", lambda o: ("192.0.2.51", "192.0.2.10")), "but this machine uses"),
    (lambda: setattr(incident, "get_proxies", lambda: {"https": "http://proxy.example:3128"}), "proxies are configured"),
]
for setup, why in cases:
    setup()
    c = incident.plan_firewall(s, f)
    assert c["refused"] and why in c["refused"] and "(override: --force-firewall)" in c["refused"], (why, c["refused"])
    c = incident.plan_firewall(s, f, override=True)  # overridden: planned, the check result kept in the note
    assert not c["refused"] and why in c["note"] and "applied because of --force-firewall" in c["note"], (why, c)
    assert next(x for x in incident.plan(s, f, args(only="firewall", force=True)))["refused"] is None
    incident.client_address = lambda origin: ("192.0.2.50", "192.0.2.10")
    incident.get_proxies = lambda: {}
for own, why in [([{"time": "2026/10/30 11:59:00", "descr": "User [ops] from [127.0.0.1] signed in to [DSM] successfully via [password]"}], "Tailscale userspace"),
                 ([{"time": "2026/10/30 11:59:00", "descr": "User [ops] from [2001:db8::5] signed in to [DSM] successfully via [password]"}], "IPv6"),
                 ([], "public address (1.2.3.4)")]:  # no own entry: the newest ops sign-in is the external one
    n2 = FakeNas()
    n2.st["own_signin"] = own
    s2 = FakeSession(n2)
    c = incident.plan_firewall(s2, incident.gather(s2, args()))
    assert c["refused"] and why in c["refused"], (why, c["refused"])
# the local backend has no network path to lock out, but needs allowed_networks
c = incident.plan_firewall(FakeSession(nas, "local"), f)
assert c["refused"] and "nothing to allow" in c["refused"], c
_env.use_config({"allowed_networks": ["192.0.2.0/24"]})
assert not incident.plan_firewall(FakeSession(nas, "local"), f)["refused"]
_env.use_config({})

# --- fix: dry run sends no write -------------------------------------------------------------------
nas = FakeNas()
lines, data, rc = incident.fix(FakeSession(nas), args(action="fix", dry_run=True))
assert rc == 0 and lines[-1] == "Dry run: nothing was sent." and all(is_read_method(m) for _, m in nas.sent), \
    [m for _, m in nas.sent if not is_read_method(m)]
text = "\n".join(lines)
assert "--allow-write" in text and "UI: Control Panel > Security > Firewall" in text and "控制台 > 安全性 > 防火牆" in text
# without --yes and without a terminal nothing is applied
nas = FakeNas()
lines, data, rc = incident.fix(FakeSession(nas), args(action="fix"))
assert rc == 3 and lines[-1] == "Not applied: add --yes (or NAS_YES=1)." and all(is_read_method(m) for _, m in nas.sent)
# auto-confirm from NAS_YES=1 or config assume_yes turns into --yes for the same command line
import os
from nas import cli
os.environ["NAS_YES"] = "1"
assert cli.parse_args(["incident", "fix"]).yes is True
del os.environ["NAS_YES"]
_env.use_config({"assume_yes": True})
a = cli.parse_args(["incident", "fix"])
assert a.yes is True and a.assume_yes is True
_env.use_config({})
a = cli.parse_args(["incident", "fix", "--json", "--force", "--no-input"])  # global switches after the command
assert a.json and a.force and a.no_input and not a.yes
assert cli.parse_args(["--yes", "incident", "fix"]).yes is True
# snapshot gate: --force works like --i-know-snapshots-may-rotate
n3 = FakeNas()
s3 = FakeSession(n3)
f3 = incident.gather(s3, args())
gate = incident.plan(s3, f3, args(only="snapshots"))
assert gate[0]["refused"] and "(override: --i-know-snapshots-may-rotate or --force)" in gate[0]["refused"]
assert not incident.plan(s3, f3, args(only="snapshots", force=True))[0]["refused"]

# --- fix: apply, read back, audit again ------------------------------------------------------------
nas = FakeNas()
lines, data, rc = incident.fix(FakeSession(nas), args(action="fix", yes=True, i_know_snapshots_may_rotate=True))
res = {(r["fix"], r["target"]): r["ok"] for r in data["results"]}
assert all(res.values()), data["results"]
after = status(data["after"])
for k in ("firewall", "quickconnect", "router_port_forwarding", "autoblock", "smb_min_protocol", "admin_account",
          "snapshot_worm:photos"):
    assert after[k] == "PASS", (k, after[k])
new = next(i for i in data["after"] if i["id"] == "snapshot_schedule:docs")
assert new["status"] == "WARN" and "schedule on" in new["detail"] and "none yet" in new["detail"], new
med = next(i for i in data["after"] if i["id"] == "snapshot_schedule:media")
assert med["status"] == "WARN" and "disabled schedule exists" in med["detail"], "existing schedules are left alone"
assert after["sa_26_14_packages"] == "WARN", "stopped but still vulnerable"
assert after["dsm_version"] == "FAIL" and rc == 1, "DSM 7.1 stays FAIL without --upgrade; exit 1"
assert nas.st["profile"]["pppoe"]["rules"] == [] and nas.st["ab_allow"] == {"192.0.2.50"}
assert all(not r["enable"] for r in nas.st["pf"]) and nas.st["pf"][0]["serviceid"] == "dsm"
assert nas.st["retention_set"]["docs"]["retainDay"] == 14
w = [m for a, m in nas.sent if not is_read_method(m)]
assert w.index("set_worm_lock") < w.index("set_schedule") < w.index("stop") < w.index("create") < w.index("start"), w
assert nas.st["admin"] == "now" and nas.st["tasks"] == {}, "admin disabled through a root task, task deleted"
assert any("Before -> after:" == l for l in lines)

# a failed read-back is reported, and the firewall failure prints the rescue steps
nas = FakeNas()
incident.fresh_login_error = lambda s: "HTTP to https://192.0.2.10:5001 failed: timed out"
lines, data, rc = incident.fix(FakeSession(nas), args(action="fix", yes=True, only="firewall"))
assert rc == 1 and not data["results"][0]["ok"] and "Synology Assistant" in "\n".join(lines), lines
incident.fresh_login_error = lambda s: None

# the admin fix needs a root task (password backend) or the local backend
c = next(c for c in incident.plan(FakeSession(FakeNas(), "chrome"), f, args(only="admin_account")))
assert c["refused"] and "--backend password" in c["refused"], c
c = next(c for c in incident.plan(FakeSession(FakeNas(), "local"), f, args(only="admin_account")))
assert not c["refused"] and [k["method"] for k in c["calls"]] == ["set"], c

# losing the connection after the changes keeps the results and prints the rescue steps
class DropAfterFirewall(FakeSession):
    def call(self, api, method, params=None, version=None, timeout=None):
        if self.nas.st.get("cut"):
            raise NasError("HTTP to https://192.0.2.10:5001 failed: timed out")
        if (api, method) == ("SYNO.Core.Security.Firewall.Profile.Apply", "stop"):
            self.nas.st["cut"] = True
            return ok(None)
        return super().call(api, method, params, version, timeout)


incident.fresh_login_error = lambda s: None
nas = FakeNas()
lines, data, rc = incident.fix(DropAfterFirewall(nas), args(action="fix", yes=True, only="smb_min_protocol,firewall"))
text = "\n".join(lines)
assert rc == 1 and data["after"] is None and "Post-fix audit could not run" in text and "Synology Assistant" in text, text
assert [r["fix"] for r in data["results"]] == ["smb_min_protocol", "firewall"] and data["results"][0]["ok"], data["results"]

# --rotate-password refuses when the password store cannot be written
nas = FakeNas()
s = FakeSession(nas)
s.backend.creds = types.SimpleNamespace(writable_store=lambda: None, source=lambda: "command")
c = incident.plan_rotation(s)
assert c["refused"] and "cannot update" in c["refused"], c
c = incident.plan_rotation(FakeSession(nas, "chrome"))
assert c["refused"] and "--backend password" in c["refused"]
# rotation: the store gets the new password before DSM; a DSM refusal puts the old one back; an interrupted
# DSM call leaves the new one in the store (1Password keeps the old one in the item history)
class Store:
    def __init__(self):
        self.value, self.log, self.cfg = "old-pw", [], {"store_service": "svc"}

    def writable_store(self):
        return "op"

    def source(self):
        return "op"

    def password(self, user=None):
        return self.value

    def write_password(self, user, pw):
        self.log.append(("store", pw == "old-pw"))
        self.value = pw

    def read_back(self, user):
        return self.value

    def remember(self, pw):
        self.log.append(("remember", None))


for outcome in ("ok", "refused", "interrupted"):
    n2 = FakeNas()
    st = Store()
    s2 = FakeSession(n2)
    s2.backend.creds = st
    calls_seen = []

    def nu(a, m, p, outcome=outcome, orig=n2.handle):
        if (a, m) == ("SYNO.Core.NormalUser", "set"):
            calls_seen.append(("dsm", list(st.log)))
            if outcome == "refused":
                return err(400)
            if outcome == "interrupted":
                raise KeyboardInterrupt
            return ok(None)
        return orig(a, m, p)
    n2.handle = nu
    c = incident.plan_rotation(s2)
    assert not c["refused"] and "never printed" in c["note"], c
    try:
        c["apply"](s2)
        result = "ok"
    except NasError:
        result = "refused"
    except KeyboardInterrupt:
        result = "interrupted"
    assert result == outcome, (outcome, result)
    assert calls_seen[0][1] == [("store", False)], "the new password is stored before DSM is asked"
    if outcome == "ok":
        assert st.value != "old-pw" and st.log[-1] == ("remember", None) and c["verify"](s2)[0]
    elif outcome == "refused":
        assert st.value == "old-pw", "DSM refused: the store gets the old password back"
    else:
        assert st.value != "old-pw", "unknown outcome: the store keeps the new password"
s2 = FakeSession(FakeNas())
s2.backend.creds = Store()
s2.backend.account = None
assert incident.plan_rotation(s2)["target"] == "ops", "account resolved through Initdata for a pasted session"

p = incident._new_password()
assert len(p) == 24 and any(ch.isupper() for ch in p) and any(ch.isdigit() for ch in p)
# an allowed network wider than a /8 stops the firewall and AutoBlock fixes, naming the entry
for wide in ("0.0.0.0/0", "10.0.0.0/7", "::/0"):
    _env.use_config({"allowed_networks": ["192.0.2.0/24", wide]})
    try:
        incident.firewall_allow_list("192.0.2.50")
        raise AssertionError(wide + " accepted")
    except NasError as e:
        assert repr(wide) in str(e) and "wider than a /8" in str(e), str(e)
    try:
        incident.fix(FakeSession(FakeNas()), args(action="fix", dry_run=True, only="firewall"))
        raise AssertionError(wide + " accepted by incident fix")
    except NasError as e:
        assert repr(wide) in str(e)
_env.use_config({"allowed_networks": ["10.0.0.0/8"]})
assert [str(n) for n in incident.configured_v4()[0]] == ["10.0.0.0/8"]
# public ranges: a /24 or narrower (an office or home address), nothing wider; private ranges of any size
for wide in ("46.0.0.0/8", "1.2.0.0/16", "2a00:1450::/32"):
    _env.use_config({"allowed_networks": [wide]})
    try:
        incident.configured_v4()
        raise AssertionError(wide + " accepted")
    except NasError as e:
        assert repr(wide) in str(e) and "public range" in str(e), str(e)
_env.use_config({"allowed_networks": ["1.2.3.0/24", "1.2.4.5/32", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]})
assert len(incident.configured_v4()[0]) == 5
_env.use_config({})
print(f"incident checks ok (python {sys.version.split()[0]})")
