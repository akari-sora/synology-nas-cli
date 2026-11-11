"""Offline checks of argument parsing, parameter encoding and parsers (ported from the private smoke test)."""
import json
import os
import sys

import _env  # noqa: F401

from nas import cli
from nas.backends import _encode_params
from nas.commands import is_read_method
from nas.upgrade import _strip_html, _version_key, _version_tuple
from nas import advisories, commands

a = cli.parse_args(["api", "SYNO.X", "list", "--version", "2", "k=v", "a=b"])
assert a.version == 2 and a.params == ["k=v", "a=b"], a
a = cli.parse_args(["api", "SYNO.X", "list", "k=v", "--version", "3", "--allow-write"])
assert a.version == 3 and a.params == ["k=v"] and a.allow_write, a
a = cli.parse_args(["--lan-origin", "https://a:5001,https://b:5001", "status"])
assert a.lan_origin == ["https://a:5001,https://b:5001"], a
a = cli.parse_args(["--dsm-origin", "https://a:5001", "status"])
assert a.lan_origin == ["https://a:5001"], a
assert is_read_method("get") and is_read_method("list_share") and not is_read_method("set")
assert is_read_method("conf_get") and is_read_method("smart_list") and not is_read_method("uninstall")
assert is_read_method("get_schedule") and is_read_method("get_worm_lock") and is_read_method("load")
assert not is_read_method("set_worm_lock") and not is_read_method("save") and not is_read_method("create")
e = _encode_params({"id": "Tailscale", "n": 3, "flag": True, "q": '"x"', "num": "20", "l": ["a"], "empty": ""}, True)
assert e == {"id": '"Tailscale"', "n": "3", "flag": "true", "q": '"x"', "num": "20", "l": '["a"]', "empty": '""'}, e
assert _encode_params({"id": "Tailscale"}, False) == {"id": "Tailscale"}
a = cli.parse_args(["pkg", "uninstall", "X", "--remove-data"])
assert a.action == "uninstall" and a.pkg_id == "X" and a.remove_data, a
a = cli.parse_args(["volume", "atime", "volume_1", "noatime"])
assert (a.volume_id, a.mode) == ("volume_1", "noatime"), a
a = cli.parse_args(["incident"])
assert a.action is None and not a.probe and not a.scan, a
a = cli.parse_args(["incident", "fix", "--dry-run", "--only", "smb_min_protocol,quickconnect", "--share", "photos"])
assert a.action == "fix" and a.dry_run and a.only == "smb_min_protocol,quickconnect" and a.share == ["photos"], a
a = cli.parse_args(["login", "--save", "--trust-device"])
assert a.save and a.trust_device, a
a = cli.parse_args(["config", "show"])
assert a.action == "show", a
assert _version_tuple("DSM 7.4.1-90080 Update 1") == (7, 4, 90080)
assert _version_tuple("DSM 7.1.1-42962 Update 9") == (7, 1, 42962)
# the Update number breaks ties on one build: Synology ships security fixes as Updates
assert _version_key("DSM 7.4.1-90080 Update 0") == (7, 4, 90080, 0)
assert _version_key("DSM 7.4.1-90080 Update 1") == (7, 4, 90080, 1)
assert _version_key("7.4.1-90080-1") == (7, 4, 90080, 1)
assert _version_key("DSM 7.4.1-90080 Update 0") < _version_key("7.4.1-90080-1")
assert _version_key("DSM 7.4.1-90080 Update 1") > _version_key("7.4.1-90080")
assert _version_key("DSM 7.3.2-86009 Update 4") < _version_key("DSM 7.3.2-86009 Update 5")
assert _strip_html("<style>x</style><div><b>A</b><br>B&amp;C</div>") == "A\nB&C"

# SA-26:13 compares (build, update) only. A higher micro version is not a substitute.
for fw in ("DSM 7.3.2-86009 Update 3", "DSM 7.4.1-1", "DSM 7.3.2-1 Update 0"):
    assert advisories.dsm_advisory_verdict(fw, "sa_26_13")["status"] == "vulnerable", fw

# (firmware, SA-26:13, SA-26:19, aggregate). Boundaries are the build just below
# and at each fixed release. 7.5 is an unlisted future branch; 7.1 has no fix.
CASES = [
    ("DSM 7.4.1-90074", "vulnerable", "vulnerable", "vulnerable"),
    ("DSM 7.4.1-90075", "patched", "vulnerable", "vulnerable"),
    ("DSM 7.4.1-90080", "patched", "vulnerable", "vulnerable"),
    ("DSM 7.4.1-90080 Update 0", "patched", "vulnerable", "vulnerable"),
    ("DSM 7.4.1-90080 Update 1", "patched", "patched", "patched"),
    ("7.4.1-90080-1", "patched", "patched", "patched"),
    ("DSM 7.4.1-90080 Update 2", "patched", "patched", "patched"),
    ("DSM 7.4.0-90080 Update 1", "patched", "vulnerable", "vulnerable"),
    ("DSM 7.4.1-1", "vulnerable", "vulnerable", "vulnerable"),
    ("DSM 7.4.2-1", "vulnerable", "patched", "vulnerable"),
    ("DSM 7.3.2-86009 Update 3", "vulnerable", "vulnerable", "vulnerable"),
    ("DSM 7.3.2-86009 Update 4", "patched", "vulnerable", "vulnerable"),
    ("DSM 7.3.2-86009 Update 5", "patched", "patched", "patched"),
    ("DSM 7.3.2-1 Update 0", "vulnerable", "vulnerable", "vulnerable"),
    ("DSM 7.3.1-86009 Update 5", "patched", "vulnerable", "vulnerable"),
    ("DSM 7.2.2-72806 Update 8", "vulnerable", "vulnerable", "vulnerable"),
    ("DSM 7.2.2-72806 Update 9", "patched", "vulnerable", "vulnerable"),
    ("DSM 7.2.2-72806 Update 10", "patched", "patched", "patched"),
    ("DSM 7.2.1-69057 Update 11", "vulnerable", "vulnerable", "vulnerable"),
    ("DSM 7.2.1-69057 Update 12", "patched", "vulnerable", "vulnerable"),
    ("DSM 7.2.1-69057 Update 13", "patched", "patched", "patched"),
    ("DSM 7.5.0-100000", "unknown", "unknown", "unknown"),
    ("DSM 7.5-100000", "unknown", "unknown", "unknown"),
    ("DSM 7.1.1-42962 Update 9", "no_fix_for_branch", "no_fix_for_branch", "no_fix_for_branch"),
    ("DSM 7.2-64570 Update 4", "no_fix_for_branch", "no_fix_for_branch", "no_fix_for_branch"),
    ("garbage", "unknown", "unknown", "unknown"),
]
for fw, sa13, sa19, overall in CASES:
    a = advisories.dsm_advisory_verdict(fw, "sa_26_13")
    b = advisories.dsm_advisory_verdict(fw, "sa_26_19")
    g = advisories.dsm_verdict(fw)
    assert a["status"] == sa13, (fw, "sa_26_13", a)
    assert b["status"] == sa19, (fw, "sa_26_19", b)
    assert g["status"] == overall and g["advisories"]["sa_26_13"]["status"] == sa13, (fw, g)
    assert g["advisories"]["sa_26_19"]["status"] == sa19, (fw, g)
    if overall == "patched":
        assert sa13 == "patched" and sa19 == "patched" and "fixed_in" not in g, (fw, g)
    elif sa19 == "vulnerable":
        assert overall != "patched" and g.get("fixed_in") == b["fixed_in"], (fw, g)
assert advisories.dsm_advisory_verdict("DSM 7.4.1-90080 Update 1", "sa_26_13")["fixed_in"] == "7.4-90075"
assert advisories.dsm_advisory_verdict("DSM 7.3.2-86009 Update 5", "sa_26_13")["fixed_in"] == "7.3-86009-4"
assert advisories.dsm_advisory_verdict("DSM 7.2.2-72806 Update 10", "sa_26_13")["fixed_in"] == "7.2.2-72806-9"
assert advisories.dsm_advisory_verdict("DSM 7.2.1-69057 Update 13", "sa_26_13")["fixed_in"] == "7.2.1-69057-12"
assert advisories.dsm_advisory_verdict("DSM 7.4.1-90080 Update 1", "sa_26_19")["fixed_in"] == "7.4.1-90080-1"
assert advisories.dsm_advisory_verdict("DSM 7.3.2-86009 Update 5", "sa_26_19")["fixed_in"] == "7.3.2-86009-5"
assert advisories.dsm_advisory_verdict("DSM 7.2.2-72806 Update 10", "sa_26_19")["fixed_in"] == "7.2.2-72806-10"
assert advisories.dsm_advisory_verdict("DSM 7.2.1-69057 Update 13", "sa_26_19")["fixed_in"] == "7.2.1-69057-13"
assert advisories.dsm_advisory_verdict("DSM 7.4.1-90080", "sa_26_19")["cves"] == ["CVE-2026-76954", "CVE-2026-85101"]
assert "cves" not in advisories.dsm_advisory_verdict("DSM 7.4.1-90080", "sa_26_13")
assert advisories.SA_26_19["published"] == "2026-11-10"
later_micro = advisories.dsm_verdict("DSM 7.4.2-1")
assert later_micro["advisories"]["sa_26_13"]["status"] == "vulnerable"
assert later_micro["advisories"]["sa_26_19"]["status"] == "patched"
# the only fix is on an older product version, so it is not offered as this box's fixed_in
assert later_micro["status"] == "vulnerable" and "fixed_in" not in later_micro, later_micro
# an Update on the build already installed is not a .pat download; the note says where it is installed
u_gap = advisories.dsm_advisory_verdict("DSM 7.4.1-90080 Update 0", "sa_26_19")
assert "Update & Restore" in u_gap["note"] and "nas upgrade --dry-run" not in u_gap["note"], u_gap
for fw in ("DSM 7.3.2-86009 Update 4", "DSM 7.2.2-72806 Update 9", "DSM 7.2.1-69057 Update 12"):
    assert "Update & Restore" in advisories.dsm_advisory_verdict(fw, "sa_26_19")["note"], fw
# a fix on another branch or a lower micro keeps the "upgrade" hint
assert "nas upgrade --dry-run" in advisories.dsm_advisory_verdict("DSM 7.4.0-90080 Update 1", "sa_26_19")["note"]
assert "nas upgrade --dry-run" in advisories.dsm_advisory_verdict("DSM 7.3.1-86009 Update 5", "sa_26_19")["note"]
# two branch notes are joined as sentences, not with a stray ".;"
joined = advisories.dsm_verdict("DSM 7.1.1-42962 Update 9")["note"]
assert ".;" not in joined and joined.count("is not covered by SA-26:") == 2, joined
gap = advisories.dsm_verdict("DSM 7.3.2-86009 Update 4")
assert gap["status"] == "vulnerable" and "SA-26:19" in gap["note"] and "patched" != gap["status"]
# status JSON keeps sa_26_13 and does not call the box patched while SA-26:19 is open
class _Sys:
    def call(self, api, method, params=None, version=None, timeout=None):
        return {"ok": True, "data": {"model": "DS000", "firmware_ver": "DSM 7.3.2-86009 Update 4",
                                     "firmware_date": "2026-01-01", "up_time": "1:00:00",
                                     "time": "2026-11-11 12:00:00", "sys_temp": 40, "ram_size": 4096}}
lines, data = commands.status(_Sys(), cli.parse_args(["status"]))
assert data["sa_26_13"]["status"] == "patched" and data["sa_26_13"]["advisory"] == "SA-26:13"
assert data["sa_26_19"]["status"] == "vulnerable" and data["dsm_patch"]["status"] == "vulnerable"
text = "\n".join(lines)
assert "SA-26:13     patched" in text and "SA-26:19     vulnerable" in text
assert "DSM patch    vulnerable" in text and "DSM patch    patched" not in text
# alert fires for an SA-26:19 gap and stays quiet when both advisories are patched
class _Alert:
    def __init__(self, fw):
        self.fw = fw
    def call_many(self, calls):
        out = []
        for c in calls:
            if c["api"] == "SYNO.Core.System":
                out.append({"ok": True, "data": {"firmware_ver": self.fw, "time": "2026-11-11 12:00:00",
                                                 "up_time": "1:00:00"}})
            elif c["api"] == "SYNO.Core.Security.Firewall":
                out.append({"ok": True, "data": {"enable_firewall": True}})
            else:
                out.append({"ok": True, "data": {}})
        return out
    def call(self, *a, **k):
        return {"ok": True, "data": {"items": [], "total": 0}}
from nas import alert
args = cli.parse_args(["alert", "--no-update"])
open_19 = [f for f in alert.alert(_Alert("DSM 7.3.2-86009 Update 4"), args)[1] if f["code"] == "dsm_unpatched"]
assert open_19 and "SA-26:19 vulnerable" in open_19[0]["message"] and "SA-26:13 patched" in open_19[0]["message"]
closed = [f for f in alert.alert(_Alert("DSM 7.4.1-90080 Update 1"), args)[1] if f["code"] == "dsm_unpatched"]
assert closed == []
old = [f for f in alert.alert(_Alert("DSM 7.1.1-42962 Update 9"), args)[1] if f["code"] == "dsm_unpatched"]
assert old and "no_fix_for_branch" in old[0]["message"]
# dsm_behind compares the Update too, so latest_dsm=7.4.1-90080-1 flags Update 0 but not Update 1
from nas import config as _cfg
_saved = _cfg.get()["latest_dsm"]
_cfg.get()["latest_dsm"] = "7.4.1-90080-1"
behind = [f for f in alert.alert(_Alert("DSM 7.4.1-90080 Update 0"), args)[1] if f["code"] == "dsm_behind"]
assert behind and "7.4.1-90080-1" in behind[0]["message"], behind
assert [f for f in alert.alert(_Alert("DSM 7.4.1-90080 Update 1"), args)[1] if f["code"] == "dsm_behind"] == []
assert [f for f in alert.alert(_Alert("DSM 7.4.1-90080 Update 9"), args)[1] if f["code"] == "dsm_behind"] == []
_cfg.get()["latest_dsm"] = _saved
assert advisories.package_verdict("PHP7.4", "7.4.33-0120")["status"] == "vulnerable"
assert advisories.package_verdict("PHP7.4", "7.4.33-0131")["status"] == "patched"
assert advisories.package_verdict("PHP7.3", "7.3.0")["status"] == "no_fix"
assert advisories.package_verdict("FileStation", "1.0") is None

# the deploy payload carries code, a launcher and the config without secrets
import io
import json
import tarfile
from nas import config, selfmon
config.get()["credentials"]["password_command"] = "echo secret"
tar = tarfile.open(fileobj=io.BytesIO(selfmon._payload()))
names = tar.getnames()
assert "bin/nas" in names and "nas/cli.py" in names and "config.json" in names, names
deployed = tar.extractfile("config.json").read().decode()
assert "echo secret" not in deployed and not {"credentials", "webhook", "session"} & set(json.loads(deployed)), deployed
script = selfmon._run_script("/volume1/@nas-alert")
assert 'NAS_CONFIG="$D/app/config.json"' in script and script.rstrip().endswith("exit 0"), script
# deploy hardening: root dir shape, quoted paths, symlinked staging folder refused, per-run success marker
assert selfmon.ROOT_DIR_RE.match("/volume1/@nas-alert") and not selfmon.ROOT_DIR_RE.match("/volume1/@x; rm -rf /")
assert not selfmon.ROOT_DIR_RE.match("/volume1/files/app") and not selfmon.ROOT_DIR_RE.match("/tmp/@x")
inst = selfmon._install_script("ab" * 32, "e30=", "/volume1/@nas-alert", "/volume1/my share/.nas-cli-deploy", "f00d")
assert "S='/volume1/my share/.nas-cli-deploy'" in inst and '[ -L "$S" ]' in inst and 'echo "DEPLOY_OK f00d"' in inst

# alert --push wants https (http only for localhost)
from nas import alert
from nas.errors import NasError
for url, good in [("https://hooks.example.net/x", True), ("http://127.0.0.1:8080/x", True),
                  ("http://hooks.example.net/x", False), ("ftp://x", False)]:
    hook = os.path.join(_env.TMP, "hook.json")
    json.dump({"url": url, "header": "Authorization: Bearer x"}, open(hook, "w"))
    try:
        alert._push_config(type("A", (), {"push": hook, "state": os.path.join(_env.TMP, "b.json")}))
        assert good, url
    except NasError as e:
        assert not good and "https://" in str(e), (url, e)

# incident fix --upgrade: PreCheck notes stop the install unless confirmed on a terminal
import types
from nas import upgrade


class UpSession:
    backend_name = "password"

    def __init__(self):
        self.sent = []
        self.backend = types.SimpleNamespace()

    def call(self, api, method, params=None, version=None, timeout=None):
        self.sent.append((api, method))
        if api == "SYNO.Core.System":
            return {"ok": True, "data": {"model": "DS000", "firmware_ver": "DSM 7.1.1-42962 Update 9"}}
        if api == "SYNO.Core.Upgrade.PreCheck":
            return {"ok": False, "error": {"code": 5223, "errors": {"can_continue": True, "message": "<b>Note</b>"}}}
        return {"ok": True, "data": {}}

    def upload(self, *a, **kw):
        return {"ok": True, "data": {"buildnumber": 90080, "upgradetype": "patch", "reboot": True}}


pat = os.path.join(_env.TMP, "x.pat")
open(pat, "wb").write(b"x")
us = UpSession()
lines, data = upgrade.upgrade(us, types.SimpleNamespace(pat=pat, dry_run=False, yes=True, force=False, wait_only=False,
                                                         download_dir=_env.TMP, lang="enu", timeout=1,
                                                         ask_on_notes=True))
assert data["action"] == "precheck-notes-not-confirmed" and ("SYNO.Core.Upgrade", "start") not in us.sent, us.sent
assert ("SYNO.Core.Upgrade.Patch", "clean") in us.sent
# colors: status words and suggested commands on a terminal only
from nas import cli as _cli
_sample = "FAIL  firewall  off\n      -> nas incident fix --only firewall\n  FAIL  -> PASS  firewall   (changed)\nSummary: 4 PASS, 1 SKIP"
_tty = sys.stdout.isatty
try:
    sys.stdout.isatty = lambda: True
    os.environ.pop("NO_COLOR", None)
    painted = _cli._paint(_sample)
    assert "\033[1;31mFAIL\033[0m" in painted and "\033[32mPASS\033[0m" in painted and "\033[2mSKIP\033[0m" in painted
    assert "\033[36m      -> nas incident fix --only firewall\033[0m" in painted and "\033[1m(changed)" in painted
    os.environ["NO_COLOR"] = "1"
    assert _cli._paint(_sample) == _sample
finally:
    os.environ.pop("NO_COLOR", None)
    sys.stdout.isatty = _tty
assert _cli._paint(_sample) == _sample or sys.stdout.isatty(), "plain when stdout is not a terminal"
print(f"offline checks ok (python {sys.version.split()[0]})")
