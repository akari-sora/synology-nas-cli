"""`pkg`, `volume` and `tailscale`: thin wrappers over the DSM calls the
Package Center, Storage Manager and the Tailscale package UI make.

Each returns (lines, data) like the commands in commands.py."""

from __future__ import annotations

import json
import sys
import time
import urllib.parse

from .backends import NasError
from .commands import need, part

# --- pkg ------------------------------------------------------------------

_PKG_ADDITIONAL = ["status", "installed_info", "startable", "dsm_apps", "install_type"]


def _packages(s) -> dict[str, dict]:
    d = need("SYNO.Core.Package", s.call("SYNO.Core.Package", "list", version=2,
                                          params={"additional": _PKG_ADDITIONAL}))
    out = {}
    for p in d.get("packages", []):
        a = p.get("additional") or {}
        path = (a.get("installed_info") or {}).get("path") or ""
        out[p["id"]] = {
            "id": p["id"], "name": p.get("name"), "version": p.get("version"),
            "status": a.get("status"), "startable": a.get("startable"),
            "install_type": a.get("install_type") or "", "path": path,
            "volume": "/" + path.split("/")[1] if path.startswith("/volume") else "system",
            "dsm_apps": (a.get("dsm_apps") or "").strip(),
        }
    return out


def _wait(fn, timeout: float, interval: float = 3.0, what: str = ""):
    deadline = time.time() + timeout
    while True:
        v = fn()
        if v:
            return v
        if time.time() > deadline:
            raise NasError(f"timed out after {timeout:.0f}s waiting for {what}")
        time.sleep(interval)


def _default_volume(s) -> str:
    return need("SYNO.Core.Package.Setting.Volume",
                s.call("SYNO.Core.Package.Setting.Volume", "get", version=1)).get("default_vol")


def pkg(s, args):
    act = args.action
    if act == "list":
        pk = _packages(s)
        lines = [f"{'id':<20} {'version':<18} {'status':<8} {'volume':<9} startable"]
        for p in sorted(pk.values(), key=lambda p: p["id"].lower()):
            lines.append(f"{p['id']:<20} {p['version']:<18} {p['status']:<8} {p['volume']:<9} "
                         f"{'yes' if p['startable'] else 'no'}")
        lines.append(f"default install volume: {_default_volume(s)}")
        return lines, {"packages": list(pk.values()), "default_volume": _default_volume(s)}

    if act == "default-volume":
        if args.pkg_id:
            vol = args.pkg_id
            need("SYNO.Core.Package.Setting.Volume",
                 s.call("SYNO.Core.Package.Setting.Volume", "set", version=1, params={"default_vol": vol}))
        cur = _default_volume(s)
        return [f"default install volume: {cur}"], {"default_volume": cur}

    if not args.pkg_id:
        raise NasError(f"`nas pkg {act}` needs a package ID (see `nas pkg list`)")
    pid = args.pkg_id

    if act in ("start", "stop"):
        pk = _packages(s)
        if pid not in pk:
            raise NasError(f"{pid} is not installed")
        need("SYNO.Core.Package.Control", s.call("SYNO.Core.Package.Control", act, version=1, params={"id": pid}))
        want = "running" if act == "start" else "stop"
        st = _wait(lambda: (_packages(s).get(pid) or {}).get("status") == want and want,
                   args.timeout, what=f"{pid} to be {want}")
        return [f"{pid}: {st}"], {"id": pid, "status": st}

    if act == "install":
        if pid in _packages(s):
            raise NasError(f"{pid} is already installed")
        vol = args.volume or _default_volume(s)
        need("SYNO.Core.Package.Installation", s.call("SYNO.Core.Package.Installation", "install", version=1, params={
            "name": pid, "blqinst": True, "volume_path": vol, "is_syno": True, "beta": False,
            "installrunpackage": True}))
        task = f"@SYNOPKG_DOWNLOAD_{pid}"

        def done():
            r = s.call("SYNO.Core.Package.Installation", "status", version=1, params={"task_id": task})
            d, e = part("SYNO.Core.Package.Installation", r)
            if d and d.get("finished"):
                code = (d.get("error") or {}).get("code")
                if code:
                    raise NasError(f"install of {pid} failed: code {code}")
                return True
            stage = (d.get("last_stage") or d.get("progress")) if d else e
            print(f"  installing {pid}… {stage}", file=sys.stderr)
            return False

        _wait(done, args.timeout, interval=5, what=f"{pid} download/install")
        p = _wait(lambda: _packages(s).get(pid), 120, what=f"{pid} to appear in the package list")
        return [f"{pid} {p['version']} installed at {p['path']} ({p['status']})"], p

    if act == "uninstall":
        pk = _packages(s)
        if pid not in pk:
            raise NasError(f"{pid} is not installed")
        g = need("SYNO.Core.Package", s.call("SYNO.Core.Package", "get", version=1,
                                              params={"id": pid, "additional": ["uninstall_pages"]}))
        pages = (g.get("additional") or {}).get("uninstall_pages")
        if isinstance(pages, str):
            try:
                pages = json.loads(urllib.parse.unquote(pages))
            except ValueError:
                pages = None
        keys = [sub["key"] for page in (pages or []) for item in page.get("items", [])
                if item.get("type") == "multiselect" for sub in item.get("subitems", []) if sub.get("key")]
        params = {"id": pid, "dsm_apps": pk[pid]["dsm_apps"]}
        if pages:
            # The wizard sends extra_values as Ext.encode(obj); with the JSON
            # request format that becomes a JSON string containing JSON.
            params["extra_values"] = json.dumps(json.dumps({k: bool(args.remove_data) for k in keys}))
        need("SYNO.Core.Package.Uninstallation",
             s.call("SYNO.Core.Package.Uninstallation", "uninstall", version=1, params=params, timeout=600))
        _wait(lambda: pid not in _packages(s), args.timeout, what=f"{pid} to disappear from the package list")
        note = f" (wizard options {', '.join(keys)} = {bool(args.remove_data)})" if keys else ""
        return [f"{pid} uninstalled{note}"], {"id": pid, "uninstalled": True, "wizard_keys": keys,
                                              "remove_data": bool(args.remove_data)}

    raise NasError(f"unknown pkg action {act!r}")


# --- volume ---------------------------------------------------------------

def _volumes(s) -> list[dict]:
    st = need("SYNO.Storage.CGI.Storage", s.call("SYNO.Storage.CGI.Storage", "load_info", version=1))
    out = []
    for v in st.get("volumes", []):
        out.append({"id": v.get("id"), "path": v.get("vol_path"), "status": v.get("status"),
                    "fs": v.get("fs_type"), "atime": v.get("atime_opt"), "desc": v.get("vol_desc") or "",
                    "pool": v.get("pool_path")})
    return out


def _capacity_warn(s, vol_path: str):
    d, _ = part("SYNO.Core.Storage.Volume", s.call("SYNO.Core.Storage.Volume", "conf_get", version=1,
                                                   params={"volume_path": vol_path}))
    return (d or {}).get("capacity_warn_percent")


def volume(s, args):
    vols = _volumes(s)
    if args.action == "list":
        lines = []
        for v in vols:
            v["capacity_warn_percent"] = _capacity_warn(s, v["path"])
            lines.append(f"{v['id']:<10} {v['path']:<9} {v['status']:<10} {v['fs']:<6} atime {v['atime']:<9} "
                         f"capacity warning {v['capacity_warn_percent']}%")
        return lines, {"volumes": vols}

    if args.action == "atime":
        if not args.volume_id or not args.mode:
            raise NasError("usage: nas volume atime VOLUME_ID {noatime|relatime}")
        v = next((x for x in vols if args.volume_id in (x["id"], x["path"])), None)
        if not v:
            raise NasError(f"no volume {args.volume_id!r} (have: {', '.join(x['id'] for x in vols)})")
        warn = _capacity_warn(s, v["path"])
        if warn is None:
            raise NasError(f"could not read capacity_warn_percent of {v['path']}; not changing anything")
        need("SYNO.Storage.CGI.Volume", s.call("SYNO.Storage.CGI.Volume", "set_setting", version=1, params={
            "space_id": v["id"], "desc": v["desc"], "atime_opt": args.mode, "capacity_warn_percent": int(warn)}))
        now = next(x for x in _volumes(s) if x["id"] == v["id"])
        return ([f"{v['id']}: atime {v['atime']} → {now['atime']} (capacity warning kept at {warn}%)"],
                {"id": v["id"], "before": v["atime"], "after": now["atime"], "capacity_warn_percent": warn})

    raise NasError(f"unknown volume action {args.action!r}")


# --- tailscale ------------------------------------------------------------

_TS = "/webman/3rdparty/Tailscale/index.cgi"


def _ts_data(s, timeout: float = 30):
    st, hdr, body, cookies = s.http_raw(_TS + "/api/data", timeout=timeout)
    if st == 404:
        raise NasError("Tailscale web UI not found (package not installed or not running? `nas pkg list`)")
    if st != 200:
        raise NasError(f"Tailscale /api/data: HTTP {st}")
    try:
        data = json.loads(body)
    except ValueError:
        raise NasError("Tailscale /api/data: not JSON (DSM session not accepted?)")
    return data, hdr, cookies


def tailscale(s, args):
    data, hdr, cookies = _ts_data(s)
    summary = {k: data.get(k) for k in ("Status", "DeviceName", "TailnetName", "DomainName", "IPv4", "IPv6",
                                        "TUNMode", "KeyExpiry", "KeyExpired", "IPNVersion", "RunningSSHServer")}
    summary["LoginName"] = (data.get("Profile") or {}).get("LoginName")
    if args.action == "status":
        lines = [
            f"Status       {summary['Status']}  (Tailscale {summary['IPNVersion']}, "
            f"{'TUN' if summary['TUNMode'] else 'userspace networking'})",
            f"Device       {summary['DeviceName'] or '-'}  tailnet {summary['TailnetName'] or '-'}  "
            f"login {summary['LoginName'] or '-'}",
            f"Addresses    {summary['IPv4']}  {summary['IPv6']}",
            f"Key expiry   {summary['KeyExpiry'] or '-'}" + ("  (EXPIRED)" if summary["KeyExpired"] else ""),
        ]
        return lines, summary

    if args.action == "login-url":
        if summary["Status"] == "Running" and not args.force:
            return [f"Already logged in as {summary['LoginName']} ({summary['IPv4']}); pass --force to reauthenticate"], summary
        csrf = hdr.get("X-Csrf-Token") or hdr.get("X-CSRF-Token")
        if not csrf:
            raise NasError("Tailscale /api/data did not send an X-Csrf-Token header")
        # Reauthenticate=false waits on the backend and never answers here;
        # true returns {"url": ...} within seconds. Each call replaces the
        # previous login link.
        body = json.dumps({"Reauthenticate": True, "ForceLogout": False}).encode()
        st, _, text, _ = s.http_raw(_TS + "/api/up", data=body, cookies=cookies, timeout=args.timeout,
                                    headers={"X-Csrf-Token": csrf, "Content-Type": "application/json"})
        if st != 200:
            raise NasError(f"Tailscale /api/up: HTTP {st}: {text[:120]}")
        try:
            url = json.loads(text).get("url")
        except ValueError:
            url = None
        if not url:
            raise NasError(f"Tailscale /api/up answered without a url: {text[:200]}")
        return [url, "Open it in a browser and approve the device; `nas tailscale status` shows Running afterwards."], \
            {"url": url}

    raise NasError(f"unknown tailscale action {args.action!r}")
