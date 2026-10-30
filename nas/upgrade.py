"""`nas upgrade`: DSM manual update (the same calls as Control Panel > Update & Restore >
Manual DSM Update / 控制台 > 更新與還原 > 手動更新 DSM).

Flow: pick the .pat (official download or --pat) → SYNO.Core.Upgrade.Patch upload
→ SYNO.Core.Upgrade.PreCheck start (prints Synology's notes) → SYNO.Core.Upgrade
start (only with --yes) → wait for the reboot and for SessionData
`dsm_upgrade_all_done`. Logins return 499 until that flag is true.
"""

from __future__ import annotations

import html
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

from . import config
from .backends import NasError, describe_error

DOWNLOAD_API = "https://www.synology.com/api/support/findDownloadInfo"
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
                return {"version": f"{item.get('build_ver')}-{item.get('build_num')}",
                        "build": int(item.get("build_num")), "required_build": int(item.get("required_num") or 0),
                        "required_version": item.get("required_ver"), "url": urls[0]}
    raise NasError(f"no .pat download found for {model}")


def _download(url: str, dest_dir: str) -> str:
    name = urllib.parse.unquote(urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1])
    os.makedirs(dest_dir, exist_ok=True)
    path = os.path.join(dest_dir, name)
    req = urllib.request.Request(url, method="HEAD")
    with urllib.request.urlopen(req, timeout=30) as r:
        size = int(r.headers.get("Content-Length") or 0)
    if size and os.path.exists(path) and os.path.getsize(path) == size:
        _log(f"using cached {path} ({size:,} bytes)")
        return path
    _log(f"downloading {name} ({size:,} bytes) to {dest_dir}")
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


def wait_until_ready(s, timeout: float, saw_down: bool = False) -> dict:
    """Poll SessionData until DSM is back and `dsm_upgrade_all_done` is true."""
    deadline, prev = time.time() + timeout, None
    while time.time() < deadline:
        sd = _session_data(s)
        state = "down" if sd is None else ("ready" if sd.get("dsm_upgrade_all_done") else "finishing")
        if state != prev:
            _log(f"{time.strftime('%H:%M:%S')} DSM {state}")
            prev = state
        if state == "down":
            saw_down = True
        elif state == "ready" and saw_down:
            return sd
        time.sleep(15)
    raise NasError(f"DSM not ready after {int(timeout)}s")


def _version_tuple(fw: str) -> tuple[int, int, int]:
    """'DSM 7.4.1-90080 Update 1' → (7, 4, 90080)."""
    m = re.search(r"(\d+)\.(\d+)(?:\.\d+)?-(\d+)", fw or "")
    if not m:
        raise NasError(f"cannot parse DSM version {fw!r}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


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
    lines = [f"Current      {model}  {fw}"]
    data = {"model": model, "current": fw}

    if args.pat:
        pat = {"version": "(from file)", "build": None, "url": None, "file": os.path.abspath(args.pat)}
    else:
        pat = latest_pat(model, major, minor)
        lines.append(f"Latest       DSM {pat['version']} (needs ≥ {pat['required_version']}-{pat['required_build']})")
        lines.append(f"Download     {pat['url'].split('?')[0]}")
        if pat["build"] <= build and not args.force:
            lines.append("Already on the latest build; nothing to do (--force to reinstall).")
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

    path = pat.get("file") or _download(pat["url"], args.download_dir)
    _log(f"uploading {os.path.basename(path)} to the NAS")
    up = s.upload("SYNO.Core.Upgrade.Patch", "upload", 1, {"target": "active"}, path)
    if not up.get("ok"):
        raise NasError("Patch upload: " + describe_error("SYNO.Core.Upgrade.Patch", up))
    lines.append(f"Uploaded     build {up['data'].get('buildnumber')} ({up['data'].get('upgradetype')}), "
                 f"reboot: {up['data'].get('reboot')}")
    data["uploaded"] = up["data"]

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
        if sys.stdin.isatty():
            sys.stderr.write("PreCheck reported the notes above. Install now (the NAS reboots)? [y/N] ")
            sys.stderr.flush()
            answer = sys.stdin.readline().strip().lower()
        if answer not in ("y", "yes"):
            s.call("SYNO.Core.Upgrade.Patch", "clean", version=1)
            lines.append("Staged patch cleaned: PreCheck reported notes and the install was not confirmed. "
                         "Read them, then run `nas upgrade --yes`.")
            data["action"] = "precheck-notes-not-confirmed"
            return lines, data

    if not can_continue or not args.yes:
        s.call("SYNO.Core.Upgrade.Patch", "clean", version=1)
        lines.append("Staged patch cleaned. " + ("PreCheck blocks this upgrade." if not can_continue
                                                  else "Re-run with --yes to install."))
        data["action"] = "precheck-only"
        return lines, data

    st = s.call("SYNO.Core.Upgrade", "start", version=1, params={"force": True, "type": "patch"})
    if not st.get("ok"):
        raise NasError("Upgrade start: " + describe_error("SYNO.Core.Upgrade", st))
    _log("upgrade started; the NAS will reboot")
    s.backend._sid = s.backend._token = None  # the session dies with the reboot
    wait_until_ready(s, args.timeout)
    after = s.call("SYNO.Core.System", "info", version=1)
    new_fw = (after.get("data") or {}).get("firmware_ver") if after.get("ok") else None
    lines.append(f"Done         {new_fw or '(log in failed: ' + describe_error('SYNO.API.Auth', after) + ')'}")
    data.update(action="installed", after=new_fw)
    return lines, data
