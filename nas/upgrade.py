"""`nas upgrade`: DSM manual update (the same calls as Control Panel > Update & Restore >
Manual DSM Update / 控制台 > 更新與還原 > 手動更新 DSM).

Flow: pick the .pat (official download or --pat) → SYNO.Core.Upgrade.Patch upload
→ SYNO.Core.Upgrade.PreCheck start (prints Synology's notes) → SYNO.Core.Upgrade
start (only with --yes) → wait for the reboot and for SessionData
`dsm_upgrade_all_done`. Logins return 499 until that flag is true.

Update packs (7.4.1-90080 Update 1, not a new build) live apart from full
images: `.../criticalupdate/update_pack/<build>-<nano>/synology_<arch>_<model>.pat`.
The Update pack route is taken when every open advisory is fixed by an Update
on the installed build, and also when the box already runs the newest full
build but Synology lists a newer Update for it. Installing a pack needs the
explicit `--install-update` flag on top of `--yes`: the flow runs end to end
against a fake DSM with Synology's real packs (tests/update_pack_e2e_check.py)
but has not yet run on a real NAS. Every pack is identified by the header dict
at its start before anything is uploaded.
"""

from __future__ import annotations

import ast
import hashlib
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from . import advisories, config
from .backends import NasError, describe_error
from .errors import can_prompt

DOWNLOAD_API = "https://www.synology.com/api/support/findDownloadInfo"
UPDATE_PACK_URL = "https://global.synologydownload.com/download/DSM/criticalupdate/update_pack"
SESSION_DATA = "/webapi/entry.cgi?api=SYNO.Core.Desktop.SessionData&version=1&method=getjs"


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.load(r)


def _download_info(model: str, major: int, minor: int) -> dict:
    q = urllib.parse.urlencode({"lang": "en-global", "product": model, "major": major, "minor": minor})
    return _get_json(f"{DOWNLOAD_API}?{q}").get("info") or {}


def latest_pat(model: str, cur_major: int, cur_minor: int) -> dict:
    """Newest published DSM for `model`: version, build, minimum required build, URL."""
    info = _download_info(model, cur_major, cur_minor)
    pub = info.get("pubVers") or []
    if not pub:
        raise NasError(f"Synology download API lists no DSM versions for {model}")
    m = re.match(r"(\d+)\.(\d+)", pub[0]["version"])
    if m and (int(m.group(1)), int(m.group(2))) != (cur_major, cur_minor):
        info = _download_info(model, int(m.group(1)), int(m.group(2)))
    for block in (info.get("system") or {}).get("detail") or []:
        for item in block.get("items") or []:
            urls = [f.get("url") for f in item.get("files") or [] if ".pat" in (f.get("url") or "")]
            if urls:
                try:
                    nano = int(item.get("latest_nano"))
                except (TypeError, ValueError):
                    nano = None
                return {"version": f"{item.get('build_ver')}-{item.get('build_num')}",
                        "build": int(item.get("build_num")), "required_build": int(item.get("required_num") or 0),
                        "required_version": item.get("required_ver"), "url": urls[0], "latest_nano": nano}
    raise NasError(f"no .pat download found for {model}")


def _latest_nano(info: dict, build: int):
    """Newest published Update number for `build`, or None when the API lists none.

    The download API only links full images, but each item carries the newest
    Update for its build (`latest_nano`).
    """
    for block in (info.get("system") or {}).get("detail") or []:
        for item in block.get("items") or []:
            try:
                same = int(item.get("build_num")) == build
                nano = int(item.get("latest_nano"))
            except (TypeError, ValueError):
                continue
            if same:
                return nano
    return None


_PACK_RE = re.compile(rb"\{'archive_type'\s*:\s*'update_pack'.*?\}", re.S)

# Observed Update-pack magics (first 4 bytes): b6adbeef on 716+, acadbeef on
# 916+. The magic varies by model, so it is only a refusal hint for --pat,
# never an identity check; the header dict is the guarantee.
_PACK_MAGICS = (b"\xb6\xad\xbe\xef", b"\xac\xad\xbe\xef")


def _pack_header(data: bytes):
    """The identity dict at the start of an Update pack, or None.

    Verified against real packs: after the magic the file carries e.g.
    `{'archive_type': 'update_pack', 'platform': 'braswell', 'buildnum':
    '90080', 'major': '7', 'minor': '4', 'productversion': '7.4.1',
    'smallfixnum': 1, 'unique': 'synology_braswell_716+'}. Full images use a
    different magic and have no such header.
    """
    m = _PACK_RE.search(data or b"")
    if not m:
        return None
    try:
        header = ast.literal_eval(m.group(0).decode("ascii"))
    except (ValueError, SyntaxError):
        return None
    return header if isinstance(header, dict) else None


def _check_update_pack(path: str, *, unique: str, build: int, branch3: str,
                       cur_update: int, min_update: int) -> dict:
    """Refuse to upload `path` unless its header names exactly this box's fix.

    Same-size packs for other models download fine, so the HTTP status and the
    file size prove nothing; the header is the guarantee. Returns the header.
    """
    with open(path, "rb") as f:
        header = _pack_header(f.read(8192))
    problems = []
    if header is None:
        problems.append("no update-pack header found")
    else:
        if header.get("unique") != unique:
            problems.append(f"pack is for {header.get('unique')}, this box is {unique}")
        if str(header.get("buildnum")) != str(build):
            problems.append(f"pack is build {header.get('buildnum')}, this box is build {build}")
        if header.get("productversion") != branch3:
            problems.append(f"pack is for {header.get('productversion')}, this box is {branch3}")
        try:
            small = int(header.get("smallfixnum"))
        except (TypeError, ValueError):
            small = None
            problems.append("pack header has no smallfixnum")
        if small is not None:
            if small <= cur_update:
                problems.append(f"pack is Update {small}, this box is already on Update {cur_update}")
            if small < min_update:
                problems.append(f"pack is Update {small}, the advisory needs Update {min_update}")
    if problems:
        raise NasError(f"{path}: not this box's Update pack ({'; '.join(problems)})")
    return header


def _update_pack_url(unique: str, build: int, nano: int) -> str:
    """`.../criticalupdate/update_pack/<build>-<nano>/synology_<arch>_<model>.pat`."""
    name = urllib.parse.quote(unique + ".pat", safe="")
    return f"{UPDATE_PACK_URL}/{build:d}-{nano:d}/{name}"


def _require_idle(s) -> None:
    """Refuse to stage anything while DSM itself is updating.

    The CLI and DSM share one staging area: uploading over DSM's own download
    (weekly auto-install included) or cleaning its staged pack breaks it.
    An unreadable status only warns: old DSM releases may not answer this API.
    """
    try:
        st = s.call("SYNO.Core.Upgrade", "status", version=1)
    except NasError as e:
        _log(f"warning: cannot read upgrade status ({e}); proceeding")
        return
    if not st.get("ok"):
        _log(f"warning: cannot read upgrade status ({describe_error('SYNO.Core.Upgrade', st)}); "
             "proceeding")
        return
    data = st.get("data") or {}
    if "status" not in data:
        _log("warning: upgrade status has no status field; proceeding")
        return
    if data.get("status") != "none":
        raise NasError(f"DSM is busy (upgrade status {data.get('status')}); "
                       "wait for Control Panel > Update & Restore to finish, then retry")


def _head(url: str) -> tuple:
    """HEAD request: (http status, Content-Length, ETag without quotes). 404s return, not raise."""
    req = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            status = r.status
            size = int(r.headers.get("Content-Length") or 0)
            etag = (r.headers.get("ETag") or "").strip().strip('"')
    except urllib.error.HTTPError as e:
        return e.code, 0, ""
    return status, size, etag


def _is_md5(etag: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{32}", etag or ""))


def _check_md5(path: str, etag: str) -> None:
    """When the CDN ETag is a bare MD5, the downloaded file must match it. Anything else: skip."""
    if not _is_md5(etag):
        return
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    if h.hexdigest().lower() != etag.lower():
        try:
            os.remove(path)
        except OSError:
            pass
        raise NasError(f"{path}: checksum mismatch (ETag {etag}); deleted, download again")


def _download(url: str, dest_dir: str, subdir: str | None = None, md5: str | None = None) -> str:
    """Fetch `url` into `dest_dir[/subdir]`, skipping the download when size matches.

    `subdir` keeps same-named packs apart: every Update pack for a box is called
    `synology_<arch>_<model>.pat` whatever the build or Update. `md5` (a CDN
    ETag) is verified after the download when it looks like a bare MD5.
    """
    name = urllib.parse.unquote(urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1])
    dest = os.path.join(dest_dir, subdir) if subdir else dest_dir
    os.makedirs(dest, exist_ok=True)
    path = os.path.join(dest, name)
    _status, size, _etag = _head(url)
    if size and os.path.exists(path) and os.path.getsize(path) == size:
        _log(f"using cached {path} ({size:,} bytes)")
        if md5:
            _check_md5(path, md5)
        return path
    _log(f"downloading {name} ({size:,} bytes) to {dest}")
    tmp = path + ".part"
    with urllib.request.urlopen(url, timeout=60) as r, open(tmp, "wb") as f:
        done, last = 0, time.time()
        while chunk := r.read(1 << 20):
            f.write(chunk)
            done += len(chunk)
            if time.time() - last > 5:
                _log(f"  {done / 1e6:.0f} / {size / 1e6:.0f} MB")
                last = time.time()
    if size and os.path.getsize(tmp) != size:
        raise NasError(f"download size mismatch: got {os.path.getsize(tmp)}, expected {size}")
    if md5:
        _check_md5(tmp, md5)
    os.replace(tmp, path)
    return path


def _strip_html(text: str) -> str:
    text = re.sub(r"<style.*?</style>", "", text or "", flags=re.S)
    text = re.sub(r"<br\s*/?>|</div>|</p>", "\n", text)
    text = re.sub(r"<[^>]+>", "", text)
    lines = [html.unescape(x).strip() for x in text.splitlines()]
    return "\n".join(x for x in lines if x)


def _session_data(s) -> dict | None:
    try:
        raw = s.backend.get_text(SESSION_DATA, timeout=8)
    except Exception:
        return None
    out = {}
    for k, v in re.findall(r'"(\w+)"\s*:\s*("[^"]*"|true|false|\d+)', raw):
        out[k] = json.loads(v)
    return out


def wait_until_ready(s, timeout: float, saw_down: bool = False, target_fw=None,
                     target_match: str = "exact", initial_fw: str | None = None) -> dict:
    """Poll SessionData until DSM is back and `dsm_upgrade_all_done` is true.

    `target_fw` additionally requires the box to report that version afterwards:
    "exact" compares (major, minor, build, Update), "micro" compares
    (major, minor, micro, build), "build" compares (major, minor, build).
    `dsm_upgrade_all_done` alone proves nothing: a ready box only counts after
    it went down, after the version was seen moving towards the target, or when
    it already differs from `initial_fw` (the version before the install). A
    box that went down and came back on the old version is an error, not a
    success. Logins during the wait answer 498/499 (not a password verdict);
    only those are waited out, other login errors raise.
    """
    deadline, prev, last_ver, seen_old = time.time() + timeout, None, 0.0, False
    while time.time() < deadline:
        sd = _session_data(s)
        state = "down" if sd is None else ("ready" if sd.get("dsm_upgrade_all_done") else "finishing")
        if state != prev:
            _log(f"{time.strftime('%H:%M:%S')} DSM {state}")
            prev = state
        if state == "down":
            saw_down = True
        elif state == "ready":
            if target_fw is None:
                if saw_down:
                    return sd
            elif time.time() - last_ver >= 60:
                last_ver = time.time()
                try:
                    d = s.call("SYNO.Core.System", "info", version=1)
                    if not d.get("ok"):
                        raise NasError(describe_error("SYNO.Core.System", d))
                    actual = (d.get("data") or {}).get("firmware_ver", "")
                except NasError as e:
                    if "498" not in str(e) and "499" not in str(e):
                        raise
                    _log(f"{time.strftime('%H:%M:%S')} DSM not ready for login ({e}); waiting")
                else:
                    if target_match == "exact":
                        same = _version_key(actual) == _version_key(target_fw)
                    elif target_match == "micro":
                        same = _product_key(actual)[:4] == _product_key(target_fw)[:4]
                    else:
                        same = _version_tuple(actual) == _version_tuple(target_fw)
                    if not same:
                        seen_old = True
                    elif saw_down or seen_old or (initial_fw is not None and actual != initial_fw):
                        return sd
                    if saw_down and not same:
                        raise NasError(f"DSM is back but still on {actual}, expected {target_fw}")
                    _log(f"{time.strftime('%H:%M:%S')} DSM ready on {actual}, waiting for {target_fw}")
        time.sleep(15)
    raise NasError(f"DSM not ready after {int(timeout)}s")


def _version_tuple(fw: str) -> tuple[int, int, int]:
    """'DSM 7.4.1-90080 Update 1' → (7, 4, 90080)."""
    m = re.search(r"(\d+)\.(\d+)(?:\.\d+)?-(\d+)", fw or "")
    if not m:
        raise NasError(f"cannot parse DSM version {fw!r}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _version_key(fw: str) -> tuple[int, int, int, int]:
    """Same, plus the Update number: 'DSM 7.4.1-90080 Update 1' and '7.4.1-90080-1' are (7, 4, 90080, 1).

    Synology ships a security fix for a build as an Update, so comparing the build alone
    cannot see that 7.4.1-90080 Update 0 is older than 7.4.1-90080-1.
    """
    major, minor, build = _version_tuple(fw)
    m = re.search(r"\d+\.\d+(?:\.\d+)?-\d+(?:(?:\s+update\s*|-)(\d+))?", fw or "", re.I)
    update = int(m.group(1)) if m and m.group(1) else 0
    return major, minor, build, update


def _product_key(fw: str):
    """(major, minor, micro, build, update): full ordering for upgrade routing.

    Unlike `_version_key` this sees micro versions, so 7.4.1-90080 counts as
    newer than 7.4.0-90080 (same build). Parses both display and release forms.
    """
    v = advisories.parse_dsm(fw)
    if not v:
        raise NasError(f"cannot parse DSM version {fw!r}")
    return tuple(int(x) for x in v["branch3"].split(".")) + (v["build"], v["update"])


def _box_unique() -> str:
    """This box's pack filename stem (`synology_braswell_716+`), from config.

    No DSM API exposes it; the download API does not list Update packs, so it
    is configured once per box instead of guessed per model.
    """
    unique = (config.get().get("dsm_unique") or "").strip()
    if not unique:
        raise NasError("cannot pick an Update pack: config `dsm_unique` is empty (on the NAS, "
                       "`grep ^unique= /etc.defaults/synoinfo.conf`, e.g. synology_braswell_716+); "
                       "or install the Update in Control Panel > Update & Restore")
    return unique


def _install(s, args, path: str, *, expected_build, target_fw, target_match: str = "exact",
             rerun_hint: str = "nas upgrade --yes", initial_fw: str | None = None):
    """Upload → PreCheck → start → wait, shared by the full and pack routes.

    `expected_build` (None skips the check) must match the upload echo or the
    staged file is cleaned and nothing starts. `target_fw` is confirmed after
    the wait; a box that comes back on the old version is an error.
    """
    lines, data = [], {}
    _require_idle(s)
    _log(f"uploading {os.path.basename(path)} to the NAS")
    up = s.upload("SYNO.Core.Upgrade.Patch", "upload", 1, {"target": "active"}, path)
    if not up.get("ok"):
        raise NasError("Patch upload: " + describe_error("SYNO.Core.Upgrade.Patch", up))
    got = up.get("data") or {}
    lines.append(f"Uploaded     build {got.get('buildnumber')} ({got.get('upgradetype')}), "
                 f"reboot: {got.get('reboot')}")
    data["uploaded"] = got
    if expected_build is not None and got.get("buildnumber") is not None \
            and str(got.get("buildnumber")) != str(expected_build):
        s.call("SYNO.Core.Upgrade.Patch", "clean", version=1)
        raise NasError(f"upload reported build {got.get('buildnumber')}, expected {expected_build}; "
                       "staged file cleaned, nothing started")
    if got.get("buildnumber") is None:
        _log("warning: upload did not echo a build number; continuing without the identity check")
    expect_reboot = got.get("reboot") not in (False, "false", "0", 0)
    if got.get("upgradetype") is None:
        _log("warning: upload did not report an upgradetype; continuing")

    pre = s.call("SYNO.Core.Upgrade.PreCheck", "start", version=1, params={"lang": args.lang, "type": "patch"},
                 timeout=300)
    err = (pre.get("error") or {}).get("errors") or {}
    can_continue = pre.get("ok") or bool(err.get("can_continue"))
    notes = _strip_html(err.get("message", "")) if err else ""
    data["precheck"] = {"ok": pre.get("ok"), "can_continue": can_continue,
                        "code": (pre.get("error") or {}).get("code"), "notes": notes}
    lines.append("PreCheck     " + ("passed" if pre.get("ok") else
                                    f"code {data['precheck']['code']}, can_continue={can_continue}"))
    if err.get("leading_note"):
        lines.append("  " + _strip_html(err["leading_note"]))
    lines += ["  " + x for x in notes.splitlines()]

    if can_continue and args.yes and not pre.get("ok") and getattr(args, "ask_on_notes", False):
        # PreCheck reported notes/warnings: show them and ask again instead of installing silently
        print("\n".join(lines[-(len(notes.splitlines()) + 2):]), file=sys.stderr)
        answer = ""
        if can_prompt():
            sys.stderr.write("PreCheck reported the notes above. Install now (the NAS reboots)? [y/N] ")
            sys.stderr.flush()
            answer = sys.stdin.readline().strip().lower()
        if answer not in ("y", "yes"):
            s.call("SYNO.Core.Upgrade.Patch", "clean", version=1)
            lines.append("Staged patch cleaned: PreCheck reported notes and the install was not confirmed. "
                         f"Read them, then run `{rerun_hint}`.")
            data["action"] = "precheck-notes-not-confirmed"
            return lines, data

    if not can_continue or not args.yes:
        s.call("SYNO.Core.Upgrade.Patch", "clean", version=1)
        lines.append("Staged patch cleaned. " + ("PreCheck blocks this upgrade." if not can_continue
                                                  else f"Re-run with {rerun_hint} to install."))
        data["action"] = "precheck-only"
        return lines, data

    st = s.call("SYNO.Core.Upgrade", "start", version=1, params={"force": True, "type": "patch"})
    if not st.get("ok"):
        raise NasError("Upgrade start: " + describe_error("SYNO.Core.Upgrade", st))
    data["start"] = st.get("data") or {}
    _log("upgrade started; the NAS will reboot" if expect_reboot else "upgrade started")
    s.backend._sid = s.backend._token = None  # the session dies with the reboot
    wait_until_ready(s, args.timeout, target_fw=target_fw, target_match=target_match,
                     initial_fw=initial_fw)
    after = s.call("SYNO.Core.System", "info", version=1)
    new_fw = (after.get("data") or {}).get("firmware_ver") if after.get("ok") else None
    lines.append(f"Done         {new_fw or '(log in failed: ' + describe_error('SYNO.API.Auth', after) + ')'}")
    data.update(action="installed", after=new_fw)
    return lines, data


def _pack_route(s, args, fw: str, unique: str, nano: int, need, lines: list, data: dict):
    """Find, download, verify and (with --install-update --yes) install Update `nano` for this build.

    `need` is the Update the open advisories require (None when the pack is
    simply the newest Update for an otherwise patched box). Nothing is
    uploaded before the header names exactly this box, build and branch.
    """
    v = advisories.parse_dsm(fw)
    build = v["build"]
    url = _update_pack_url(unique, build, nano)
    status, size, etag = _head(url)
    pack = {"update": nano, "needed": need, "url": url, "status": status, "size": size}
    if status != 200:
        lines.append(f"No Update pack at {url} (HTTP {status}); install Update {nano} in "
                     "Control Panel > Update & Restore.")
        data.update(pack=pack, action="none")
        return lines, data
    lines.append(f"Update pack  DSM {v['branch3']}-{build} Update {nano} ({size:,} bytes, {url})")
    data["pack"] = pack
    if args.dry_run:
        lines.append("Dry run: pack found; nothing downloaded or uploaded. "
                     "Run `nas upgrade` to download and verify it, or "
                     "`nas upgrade --install-update --yes` to download, verify and install it.")
        data["action"] = "dry-run"
        return lines, data
    path = _download(url, args.download_dir, subdir=f"{build:d}-{nano:d}", md5=etag)
    header = _check_update_pack(path, unique=unique, build=build, branch3=v["branch3"],
                                cur_update=v["update"], min_update=need or 0)
    if int(header["smallfixnum"]) != nano:
        raise NasError(f"{path}: header says Update {header['smallfixnum']}, but it was published as "
                       f"Update {nano}; refusing to upload")
    target = f"DSM {header['productversion']}-{header['buildnum']} Update {header['smallfixnum']}"
    lines.append(f"Verified     header ok: {header['unique']}, build {header['buildnum']}, "
                 f"Update {header['smallfixnum']}" + (", checksum ok" if _is_md5(etag) else ""))
    data["target"] = {"version": f"{header['productversion']}-{header['buildnum']}-{header['smallfixnum']}",
                      "build": build, "update": int(header["smallfixnum"]),
                      "url": url, "file": path, "update_pack": True}
    if not (getattr(args, "install_update", False) and args.yes):
        lines.append(f"Run `nas upgrade --install-update --yes` to upload and install it "
                     f"(or `nas upgrade --pat {path} --yes`).")
        data["action"] = "downloaded"
        return lines, data
    ilines, idata = _install(s, args, path, expected_build=build, target_fw=target,
                             target_match="exact", rerun_hint="nas upgrade --install-update --yes",
                             initial_fw=fw)
    return lines + ilines, {**data, **idata}


def upgrade(s, args):
    if s.backend_name != "password":
        raise NasError("`nas upgrade` needs --backend password (it uploads a file)")

    if args.wait_only:
        sd = wait_until_ready(s, args.timeout, saw_down=True)
        return [f"DSM ready, dsm_upgrade_all_done = {sd.get('dsm_upgrade_all_done')}"], {"ready": True}

    sysinfo = s.call("SYNO.Core.System", "info", version=1)
    if not sysinfo.get("ok"):
        raise NasError("SYNO.Core.System.info: " + describe_error("SYNO.Core.System", sysinfo))
    model, fw = sysinfo["data"]["model"], sysinfo["data"]["firmware_ver"]
    major, minor, build = _version_tuple(fw)
    cur_key = _product_key(fw)
    lines = [f"Current      {model}  {fw}"]
    data = {"model": model, "current": fw}

    if args.pat:
        # A hand-picked file: full images keep the legacy path; Update packs
        # are identified before anything is uploaded (same-size packs for
        # other models download fine, so size proves nothing). A file that
        # looks like an Update pack but has no readable header is refused, not
        # treated as a full image: its type is known, its identity is not.
        # (Pack magic varies by model -- b6adbeef on 716+, acadbeef on 916+ --
        # so both the known magics and the marker string trigger the refusal;
        # full images, magic 15adbeef, contain no such marker.)
        path = os.path.abspath(args.pat)
        with open(path, "rb") as f:
            raw = f.read(8192)
        header = _pack_header(raw)
        if header is None:
            if raw[:4] in _PACK_MAGICS or b"update_pack" in raw:
                raise NasError(f"{path}: looks like an Update pack but its header is unreadable; "
                               "refusing to upload an unidentified file")
            data["target"] = {"version": "(from file)", "build": None, "url": None, "file": path}
            ilines, idata = _install(s, args, path, expected_build=None, target_fw=None,
                                     target_match="micro", rerun_hint=f"nas upgrade --pat {path} --yes")
            return lines + ilines, {**data, **idata}
        unique = _box_unique()
        v = advisories.parse_dsm(fw)
        need = advisories.needed_update(fw) or 0
        header = _check_update_pack(path, unique=unique, build=v["build"], branch3=v["branch3"],
                                    cur_update=v["update"], min_update=need)
        ver = f"{header['productversion']}-{header['buildnum']} Update {header['smallfixnum']}"
        lines.append(f"Pack         DSM {ver} (header ok: {header['unique']})")
        data["target"] = {"version": f"{header['productversion']}-{header['buildnum']}-{header['smallfixnum']}",
                          "build": v["build"], "update": int(header["smallfixnum"]),
                          "url": None, "file": path, "update_pack": True}
        ilines, idata = _install(s, args, path, expected_build=v["build"], target_fw=f"DSM {ver}",
                                 target_match="exact", rerun_hint=f"nas upgrade --pat {path} --yes",
                                 initial_fw=fw)
        return lines + ilines, {**data, **idata}

    if advisories.update_gap_only(fw):
        # Every open advisory is an Update on this build: the Update pack
        # route, not a full image (F4: this check comes before any build
        # lookup, so 7.3.2-86009 Update 4 no longer errors on 7.4's requirement).
        need = advisories.needed_update(fw)
        unique = _box_unique()
        nano = _latest_nano(_download_info(model, major, minor), build)
        if nano is None:
            lines.append(f"Synology lists no Update pack info for build {build}; install the Update in "
                         "Control Panel > Update & Restore.")
            data.update(action="none")
            return lines, data
        if nano < need:
            lines.append(f"Synology's newest Update for build {build} is Update {nano}, but the advisory needs "
                         f"Update {need}; nothing to download (retry after Synology publishes it, or check "
                         "Control Panel > Update & Restore).")
            data.update(pack={"update": nano, "needed": need}, action="none")
            return lines, data
        return _pack_route(s, args, fw, unique, nano, need, lines, data)

    pat = latest_pat(model, major, minor)
    lines.append(f"Latest       DSM {pat['version']} (needs ≥ {pat['required_version']}-{pat['required_build']})")
    lines.append(f"Download     {pat['url'].split('?')[0]}")
    pat_key = _product_key("DSM " + pat["version"])
    if pat_key[:4] == cur_key[:4] and pat.get("latest_nano") is not None \
            and pat["latest_nano"] > cur_key[4]:
        # Newest full build already installed, but Synology lists a newer
        # Update for it: that is an Update pack, not a full image.
        data["latest"] = pat
        if not (config.get().get("dsm_unique") or "").strip():
            # no advisory needs it: report it instead of failing on the missing setting
            lines.append(f"Synology lists Update {pat['latest_nano']} for build {build}; set `dsm_unique` in the "
                         "config (on the NAS: `grep ^unique= /etc.defaults/synoinfo.conf`) to let `nas upgrade` "
                         "fetch and verify it, or install it in Control Panel > Update & Restore.")
            data.update(pack={"update": pat["latest_nano"], "needed": None}, action="none")
            return lines, data
        return _pack_route(s, args, fw, _box_unique(), pat["latest_nano"], None, lines, data)
    if pat_key < cur_key:
        if args.force:
            raise NasError(f"target DSM {pat['version']} is older than {fw}; --force does not downgrade")
        lines.append("Already on the latest build and Update; nothing to do.")
        data.update(latest=pat, action="none")
        return lines, data
    if pat_key == cur_key and not args.force:
        # Same product version and build (a newer micro shares the build
        # number, e.g. 7.4.0-90080 vs 7.4.1-90080, and does NOT land here).
        lines.append(f"Already on the newest full build (build {build}) and Synology lists no newer "
                     "Update for it; nothing to download.")
        data.update(latest=pat, action="none")
        return lines, data
    if build < pat["required_build"]:
        raise NasError(f"current build {build} is below the required {pat['required_build']}; "
                       "install an intermediate version first (--pat FILE)")
    data["target"] = pat

    if args.dry_run:
        lines.append("Dry run: nothing downloaded or uploaded.")
        data["action"] = "dry-run"
        return lines, data

    path = _download(pat["url"], args.download_dir)
    ilines, idata = _install(s, args, path, expected_build=pat["build"],
                             target_fw="DSM " + pat["version"], target_match="micro",
                             initial_fw=fw)
    return lines + ilines, {**data, **idata}
