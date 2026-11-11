"""Offline checks for the DSM Update-pack route in nas/upgrade.py (no NAS, no network).

Fakes stand in for urllib, the download API and the DSM session; the pack
bytes are crafted locally, so the header identity check runs for real.
"""
import hashlib
import os
import sys
import types
import urllib.request

import _env  # noqa: F401

from nas import advisories, cli, config
from nas.backends import NasError
from nas import upgrade

upgrade.time.sleep = lambda s: None  # no waiting in tests


def good_pack(unique="synology_braswell_716+", build="90080", productversion="7.4.1", smallfixnum=1):
    header = ("{'archive_type': 'update_pack', 'platform': 'braswell', "
              f"'buildnum': '{build}', 'major': '7', 'minor': '4', "
              f"'productversion': '{productversion}', 'smallfixnum': {smallfixnum}, "
              f"'unique': '{unique}'}}")
    return b"\xb6\xad\xbe\xef" + b"\x00" * 238 + header.encode("ascii") + b"\x00" * 4096


# --- pure helpers -----------------------------------------------------------------

h = upgrade._pack_header(good_pack())
assert h["unique"] == "synology_braswell_716+" and h["smallfixnum"] == 1, h
assert h["buildnum"] == "90080" and h["productversion"] == "7.4.1", h
assert upgrade._pack_header(b"\x15\xad\xbe\xef" + b"\x00" * 8000) is None
assert upgrade._pack_header(b"too short") is None
assert upgrade._pack_header(good_pack()[:100]) is None  # truncated before the header
assert upgrade._pack_header(b"{'archive_type': 'update_pack', broken") is None
assert upgrade._pack_header(b"{'archive_type': 'update_pack', 'unique': 'a}b'}") is None

assert upgrade._update_pack_url("synology_braswell_716+", 90080, 1) == \
    ("https://global.synologydownload.com/download/DSM/criticalupdate/update_pack"
     "/90080-1/synology_braswell_716%2B.pat")

info = {"system": {"detail": [{"items": [
    {"build_ver": "7.4.1", "build_num": "90080", "latest_nano": 1},
    {"build_ver": "7.4", "build_num": "90075", "latest_nano": 0},
]}]}}
assert upgrade._latest_nano(info, 90080) == 1
assert upgrade._latest_nano(info, 1) is None
assert upgrade._latest_nano({}, 90080) is None

assert upgrade._product_key("DSM 7.4.1-90080 Update 1") == (7, 4, 1, 90080, 1)
assert upgrade._product_key("7.4.1-90080-1") == (7, 4, 1, 90080, 1)
assert upgrade._product_key("DSM 7.4.0-90080") < upgrade._product_key("DSM 7.4.1-90080")
assert upgrade._product_key("DSM 7.3.2-86009 Update 5") < upgrade._product_key("DSM 7.4.1-90080")

# integrity: a wrong ETag deletes the file; a non-MD5 ETag is skipped
import tempfile
fd, tmp_path = tempfile.mkstemp()
os.write(fd, good_pack())
os.close(fd)
upgrade._check_md5(tmp_path, hashlib.md5(good_pack()).hexdigest())
assert os.path.exists(tmp_path)
try:
    upgrade._check_md5(tmp_path, "0" * 32)
    raise AssertionError("bad md5 accepted")
except NasError:
    pass
assert not os.path.exists(tmp_path)
fd, tmp_path = tempfile.mkstemp()
os.write(fd, good_pack())
os.close(fd)
upgrade._check_md5(tmp_path, '"some-weak-etag"')  # not an MD5: skipped, file kept
assert os.path.exists(tmp_path)
os.remove(tmp_path)

# --- fakes ------------------------------------------------------------------------

_saved_unique = config.get()["dsm_unique"]
config.get()["dsm_unique"] = "synology_braswell_716+"

_real_head = upgrade._head
_real_download = upgrade._download
_real_download_info = upgrade._download_info


class FakeBackend:
    def __init__(self):
        self._sid = "sid"
        self._token = "tok"
        self.session_data = '{"dsm_upgrade_all_done": true}'

    def get_text(self, url, timeout=None):
        if self.session_data is None:
            raise OSError("down")
        return self.session_data


class FakeSession:
    backend_name = "password"

    def __init__(self, fw, upload_data=None, status="none", info_script=None):
        self.calls = []
        self.fw = fw
        self.upload_data = {"buildnumber": 90080, "upgradetype": "nano", "reboot": False} \
            if upload_data is None else upload_data
        self.status = status
        self.info_script = info_script  # optional list of firmware_ver to serve, then last repeats
        self.cleaned = 0
        self.backend = FakeBackend()

    def call(self, api, method, params=None, version=None, timeout=None):
        self.calls.append((api, method, version))
        if (api, method) == ("SYNO.Core.System", "info"):
            if self.info_script:
                fw = self.info_script.pop(0) if len(self.info_script) > 1 else self.info_script[0]
            else:
                fw = self.fw
            return {"ok": True, "data": {"model": "DS716+", "firmware_ver": fw}}
        if (api, method) == ("SYNO.Core.Upgrade", "status"):
            if isinstance(self.status, Exception):
                raise self.status
            if isinstance(self.status, dict):
                return self.status
            return {"ok": True, "data": {"status": self.status, "allow_upgrade": True}}
        if (api, method) == ("SYNO.Core.Upgrade.PreCheck", "start"):
            return {"ok": True}
        if (api, method) == ("SYNO.Core.Upgrade", "start"):
            return {"ok": True, "data": {}}
        if (api, method) == ("SYNO.Core.Upgrade.Patch", "clean"):
            self.cleaned += 1
            return {"ok": True}
        raise AssertionError(f"unexpected call {(api, method)}")

    def upload(self, api, method, version, fields, path):
        self.calls.append((api, method, version))
        assert os.path.exists(path), path
        return {"ok": True, "data": dict(self.upload_data)}


def up_args(**kw):
    base = dict(pat=None, dry_run=False, yes=False, force=False, install_update=False,
                wait_only=False, download_dir=_env.TMP, lang="enu", timeout=60,
                ask_on_notes=False)
    base.update(kw)
    return types.SimpleNamespace(**base)


FW0 = "DSM 7.4.1-90080 Update 0"
FW1 = "DSM 7.4.1-90080 Update 1"


def stub_discovery(head=(200, 5340602, "faf9c1f6c2456ebe1df4e892b31ec646"), nano=1):
    upgrade._download_info = lambda model, major, minor: info
    upgrade._head = lambda url: head
    assert upgrade._latest_nano(info, 90080) == nano


def stub_download(pack_bytes=None):
    blob = good_pack() if pack_bytes is None else pack_bytes

    def fake_download(url, dest_dir, subdir=None, md5=None):
        assert subdir == "90080-1", subdir  # same-named packs never share a directory
        dest = os.path.join(dest_dir, subdir)
        os.makedirs(dest, exist_ok=True)
        path = os.path.join(dest, "synology_braswell_716+.pat")
        with open(path, "wb") as f:
            f.write(blob)
        # the fake CDN is always self-consistent; integrity itself is unit-tested below
        upgrade._check_md5(path, hashlib.md5(blob).hexdigest())
        return path

    upgrade._download = fake_download


def restore_net():
    upgrade._head = _real_head
    upgrade._download = _real_download
    upgrade._download_info = _real_download_info


# --- routing: pure Update gap -----------------------------------------------------

stub_discovery()
s = FakeSession(FW0)
lines, data = upgrade.upgrade(s, up_args(dry_run=True))
restore_net()
text = "\n".join(lines)
assert data["action"] == "dry-run", data
assert "90080-1" in text and "synology_braswell_716%2B.pat" in text, text
assert s.calls == [("SYNO.Core.System", "info", 1)], s.calls  # read-only: no upload, no clean

stub_discovery()
stub_download()
s = FakeSession(FW0)
lines, data = upgrade.upgrade(s, up_args())
restore_net()
text = "\n".join(lines)
assert data["action"] == "downloaded", data
assert data["target"]["update_pack"] and data["target"]["update"] == 1, data
assert "--install-update --yes" in text, text
assert s.calls == [("SYNO.Core.System", "info", 1)], s.calls
assert data["target"]["file"].endswith("90080-1/synology_braswell_716+.pat")

# wrong-model pack with the same size: the header, not HTTP/the size, blocks it
stub_discovery()
stub_download(good_pack(unique="synology_braswell_916+"))
s = FakeSession(FW0)
try:
    upgrade.upgrade(s, up_args())
    raise AssertionError("wrong-model pack accepted")
except NasError as e:
    assert "916+" in str(e), e
restore_net()
assert s.calls == [("SYNO.Core.System", "info", 1)], s.calls

# install path: status idle, matching upload echo, PreCheck ok, version confirms
stub_discovery()
stub_download()
s = FakeSession(FW0, info_script=[FW0, FW1])  # starts on Update 0, reports Update 1 after the install
lines, data = upgrade.upgrade(s, up_args(install_update=True, yes=True))
restore_net()
assert data["action"] == "installed" and data["after"] == FW1, data
assert ("SYNO.Core.Upgrade", "start", 1) in s.calls, s.calls
assert s.cleaned == 0, s.calls

# busy DSM: refused before any upload, and nothing staged is cleaned
stub_discovery()
stub_download()
s = FakeSession(FW0, status="downloading")
try:
    upgrade.upgrade(s, up_args(install_update=True, yes=True))
    raise AssertionError("busy box accepted")
except NasError as e:
    assert "busy" in str(e), e
restore_net()
assert ("SYNO.Core.Upgrade.Patch", "upload", 1) not in s.calls, s.calls
assert s.cleaned == 0, s.calls

# an unreadable upgrade status warns but proceeds (old DSM may lack the API)
stub_discovery()
stub_download()
s = FakeSession(FW0, info_script=[FW0, FW1], status=NasError("no such api"))
lines, data = upgrade.upgrade(s, up_args(install_update=True, yes=True))
restore_net()
assert data["action"] == "installed", data

# ok:false or a missing status field: warned, not treated as busy
for bad_status in ({"ok": False, "error": {"code": 103}}, {"ok": True, "data": {}}):
    stub_discovery()
    stub_download()
    s = FakeSession(FW0, info_script=[FW0, FW1], status=bad_status)
    lines, data = upgrade.upgrade(s, up_args(install_update=True, yes=True))
    restore_net()
    assert data["action"] == "installed", (bad_status, data)

# upload echo names another build: clean the stage, never start
stub_discovery()
stub_download()
s = FakeSession(FW0, upload_data={"buildnumber": 86009, "upgradetype": "nano", "reboot": False})
try:
    upgrade.upgrade(s, up_args(install_update=True, yes=True))
    raise AssertionError("mismatched upload accepted")
except NasError as e:
    assert "86009" in str(e), e
restore_net()
assert s.cleaned == 1, s.calls
assert ("SYNO.Core.Upgrade", "start", 1) not in s.calls, s.calls

# published Update is older than the advisory need: refuse before download
upgrade._download_info = lambda model, major, minor: info
s = FakeSession("DSM 7.4.1-90080 Update 0")
s.calls = []
saved_check = advisories.needed_update
advisories.needed_update = lambda fw: 2
try:
    lines, data = upgrade.upgrade(s, up_args(dry_run=True))
    assert data["action"] == "none" and "Update 2" in "\n".join(lines), (lines, data)
finally:
    advisories.needed_update = saved_check
    restore_net()

# missing dsm_unique: a clear setup error, not a wrong pack
config.get()["dsm_unique"] = ""
s = FakeSession(FW0)
try:
    upgrade.upgrade(s, up_args(dry_run=True))
    raise AssertionError("missing unique accepted")
except NasError as e:
    assert "dsm_unique" in str(e), e
config.get()["dsm_unique"] = "synology_braswell_716+"

# --- routing: full builds ---------------------------------------------------------

full_info = {"system": {"detail": [{"items": [
    {"build_ver": "7.4.1", "build_num": "90080", "required_ver": "7.4",
     "required_num": "90075",
     "files": [{"url": "https://example.invalid/DSM_DS716%2B_90080.pat?x=1"}]},
]}]}, "pubVers": [{"version": "7.4.1-90080"}]}
upgrade._download_info = lambda model, major, minor: full_info
s = FakeSession(FW1)
lines, data = upgrade.upgrade(s, up_args(dry_run=True))
restore_net()
assert data["action"] == "none" and "Already on the latest build" in "\n".join(lines), (lines, data)
assert "--force" not in "\n".join(lines)  # --force would refuse the downgrade, so don't offer it

# same build, older micro: the full 7.4.1 image is an upgrade for a 7.4.0 box
s = FakeSession("DSM 7.4.0-90080")
upgrade._download_info = lambda model, major, minor: full_info
lines, data = upgrade.upgrade(s, up_args(dry_run=True))
restore_net()
assert data["action"] == "dry-run" and data["target"]["version"] == "7.4.1-90080", (lines, data)

# --force never downgrades: full 90080 (Update 0) over Update 1 is refused
s = FakeSession(FW1)
upgrade._download_info = lambda model, major, minor: full_info
try:
    upgrade.upgrade(s, up_args(force=True))
    raise AssertionError("downgrade accepted")
except NasError as e:
    assert "downgrade" in str(e), e
restore_net()

# --pat with a verified pack installs with plain --yes (a person typed the file)
import tempfile
fd, pat_path = tempfile.mkstemp(suffix=".pat")
os.write(fd, good_pack())
os.close(fd)
s = FakeSession(FW0, info_script=[FW0, FW1])
lines, data = upgrade.upgrade(s, up_args(pat=pat_path, yes=True))
assert data["action"] == "installed" and data["target"]["update_pack"], data
os.remove(pat_path)

# --pat with a wrong-model file is refused before upload
fd, pat_path = tempfile.mkstemp(suffix=".pat")
os.write(fd, good_pack(unique="synology_braswell_716+II"))
os.close(fd)
s = FakeSession(FW0)
try:
    upgrade.upgrade(s, up_args(pat=pat_path, yes=True))
    raise AssertionError("wrong --pat accepted")
except NasError as e:
    assert "716+II" in str(e), e
assert ("SYNO.Core.Upgrade.Patch", "upload", 1) not in s.calls, s.calls
os.remove(pat_path)

# --pat with pack magic but an unreadable header is refused, never a full image
fd, pat_path = tempfile.mkstemp(suffix=".pat")
os.write(fd, b"\xb6\xad\xbe\xef" + b"\x00" * 8192)
os.close(fd)
s = FakeSession(FW0)
try:
    upgrade.upgrade(s, up_args(pat=pat_path, yes=True))
    raise AssertionError("headerless pack accepted")
except NasError as e:
    assert "unreadable" in str(e), e
assert ("SYNO.Core.Upgrade.Patch", "upload", 1) not in s.calls, s.calls
os.remove(pat_path)

# --- wait_until_ready ---------------------------------------------------------------

import time as _time

_real_time, _real_sleep = _time.time, upgrade.time.sleep
_now = [1000000.0]
upgrade.time.time = lambda: _now[0]
upgrade.time.sleep = lambda s: _now.__setitem__(0, _now[0] + s)


class WaitBackend:
    def __init__(self, script):
        self.script = list(script)
        self._sid = "s"
        self._token = "t"

    def get_text(self, url, timeout=None):
        if not self.script:
            return '{"dsm_upgrade_all_done": true}'
        item = self.script.pop(0)
        if item is None:
            raise OSError("down")
        return item


class WaitSession(FakeSession):
    def __init__(self, fw_versions, script):
        super().__init__(fw_versions[0])
        self.backend = WaitBackend(script)
        self.info_script = list(fw_versions)



READY = '{"dsm_upgrade_all_done": true}'
BUSY = '{"dsm_upgrade_all_done": false}'

try:
    # ready+done on the first poll with a reboot expected: not a success (times out)
    ws = WaitSession([FW0], [READY])
    try:
        upgrade.wait_until_ready(ws, 0.01, target_fw=FW1, target_match="exact")
        raise AssertionError("instant ready accepted")
    except NasError as e:
        assert "not ready" in str(e), e

    # version flips with a reboot expected but never observed still count when seen
    ws = WaitSession([FW0, FW1], [READY, READY])
    sd = upgrade.wait_until_ready(ws, 300, target_fw=FW1, target_match="exact")
    assert sd.get("dsm_upgrade_all_done"), sd

    # down, back on the old version: an error, not a success
    ws = WaitSession([FW0], [None, READY])
    try:
        upgrade.wait_until_ready(ws, 60, target_fw=FW1, target_match="exact")
        raise AssertionError("stale version accepted")
    except NasError as e:
        assert "still on" in str(e), e

    # full-image wait: micro equality is required (7.4.0 vs the 7.4.1 image)
    ws = WaitSession(["DSM 7.4.1-90080"], [None, READY])
    sd = upgrade.wait_until_ready(ws, 60, target_fw="DSM 7.4.1-90080", target_match="micro")
    assert sd.get("dsm_upgrade_all_done"), sd

    # down, back on the older micro: an error, not a success
    ws = WaitSession(["DSM 7.4.0-90080"], [None, READY])
    try:
        upgrade.wait_until_ready(ws, 60, target_fw="DSM 7.4.1-90080", target_match="micro")
        raise AssertionError("stale micro accepted")
    except NasError as e:
        assert "still on" in str(e), e

    # --wait-only keeps the old shape (no target, needs a down first)
    ws = WaitSession([FW0], [None, READY])
    sd = upgrade.wait_until_ready(ws, 60, saw_down=True)
    assert sd.get("dsm_upgrade_all_done"), sd
finally:
    upgrade.time.time = _real_time
    upgrade.time.sleep = _real_sleep

config.get()["dsm_unique"] = _saved_unique
print(f"upgrade checks ok (python {sys.version.split()[0]})")
