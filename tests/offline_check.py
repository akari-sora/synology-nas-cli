"""Offline checks of argument parsing, parameter encoding and parsers (ported from the private smoke test)."""
import json
import os
import sys

import _env  # noqa: F401

from nas import cli
from nas.backends import _encode_params
from nas.commands import is_read_method
from nas.upgrade import _strip_html, _version_tuple
from nas import advisories

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
assert _strip_html("<style>x</style><div><b>A</b><br>B&amp;C</div>") == "A\nB&C"

# SA-26:13 / SA-26:14 verdicts
assert advisories.dsm_verdict("DSM 7.4.1-90080 Update 1")["status"] == "patched"
assert advisories.dsm_verdict("DSM 7.3.2-86009 Update 3")["status"] == "vulnerable"
assert advisories.dsm_verdict("DSM 7.3.2-86009 Update 4")["status"] == "patched"
assert advisories.dsm_verdict("DSM 7.2.1-69057 Update 12")["status"] == "patched"
assert advisories.dsm_verdict("DSM 7.1.1-42962 Update 9")["status"] == "no_fix_for_branch"
assert advisories.dsm_verdict("garbage")["status"] == "unknown"
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
