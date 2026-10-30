"""`nas alert`: one pass of health/security checks for a scheduler.

Exit status: 0 when nothing is at warning/critical level, 1 otherwise
(info-level findings alone keep 0). Each finding is
{level, code, kind, message}:
- kind "condition": true right now; repeats on every run while it lasts.
- kind "event": something that happened since the previous run; reported once.

State between runs lives in a small JSON file (config alert.state_file):
per-disk Power_Cycle_Count, the NAS boot time, and the newest
connection-log entry already looked at.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request

from . import advisories, config
from .backends import NasError
from .commands import _ip_of, fetch_connection_log, need, part, snapshot_state
from .manage import _ts_data
from .upgrade import _version_tuple


def default_state() -> str:
    return config.path(config.get()["alert"]["state_file"])

# --push: a warning/critical condition that is still there is sent again after this long
PUSH_REMIND = dt.timedelta(hours=24)
# --push: consecutive failed runs before "alert_failed" is sent
PUSH_FAIL_AFTER = 3
# --push: events kept for resending after a failed POST
PUSH_PENDING_MAX = 50
# --push: the first run at/after this hour each day reports even when nothing changed
HEARTBEAT_HOUR = 9

_LOG_USER = re.compile(r"User \[([^\]]*)\]")
_LOG_FROM = re.compile(r"from \[([^\]]*)\]")
_LOG_VIA = re.compile(r"via \[([^\]]*)\]")


def allowed_networks() -> list:
    """config allowed_networks as ip_network objects (empty list = "every non-global address")."""
    try:
        return [ipaddress.ip_network(n, strict=False) for n in config.get()["allowed_networks"]]
    except ValueError as e:
        raise NasError(f"allowed_networks: {e}")


def _allowed(ip: str, nets: list | None = None) -> bool:
    """Sign-ins from here are expected. Tailscale in userspace mode reaches DSM as 127.0.0.1."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    nets = allowed_networks() if nets is None else nets
    if not nets:
        return not a.is_global
    return any(a.version == n.version and a in n for n in nets)


def _boot_time(sysinfo: dict) -> str | None:
    try:
        now = dt.datetime.strptime(sysinfo["time"], "%Y-%m-%d %H:%M:%S")
        h, m, sec = (int(x) for x in sysinfo["up_time"].split(":"))
    except (KeyError, ValueError):
        return None
    # minute precision: up_time and time are read a moment apart
    return (now - dt.timedelta(hours=h, minutes=m, seconds=sec)).strftime("%Y-%m-%d %H:%M")


def _load_state(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except ValueError:
        raise NasError(f"{path} is not valid JSON; delete it to start a new baseline")


def _save_state(path: str, state: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(path) + ".", dir=os.path.dirname(path))
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _newest_recording_local(root: str, cam: str) -> float | None:
    """mtime of the newest file in the 3 newest sub-folders (same walk as the FileStation path)."""
    try:
        hours = sorted((e for e in os.scandir(os.path.join(root, cam)) if e.is_dir()),
                       key=lambda e: e.name, reverse=True)[:3]
    except OSError:
        return None
    for h in hours:
        try:
            mtimes = [e.stat().st_mtime for e in os.scandir(h.path) if e.is_file()]
        except OSError:
            continue
        if mtimes:
            return max(mtimes)
    return None


def _power_cycles(smart: dict | None) -> int | None:
    for row in (smart or {}).get("smartInfo") or []:
        if str(row.get("id")) == "12" or "Power_Cycle" in str(row.get("name")):
            try:
                return int(row.get("raw"))
            except (TypeError, ValueError):
                return None
    return None


def alert(s, args):
    findings: list[dict] = []

    def add(level, code, kind, message):
        findings.append({"level": level, "code": code, "kind": kind, "message": message})

    r_sys, r_fw, r_st, r_ups, r_pkg, r_upd = s.call_many([
        {"api": "SYNO.Core.System", "method": "info", "version": 1},
        {"api": "SYNO.Core.Security.Firewall", "method": "get"},
        {"api": "SYNO.Storage.CGI.Storage", "method": "load_info", "version": 1},
        {"api": "SYNO.Core.ExternalDevice.UPS", "method": "get"},
        {"api": "SYNO.Core.Package", "method": "list", "version": 2, "params": {"additional": ["installed_info"]}},
        {"api": "SYNO.Core.Upgrade.Server", "method": "check", "version": 2},
    ])
    sysinfo = need("SYNO.Core.System", r_sys)
    checks = 0

    # firewall
    checks += 1
    fw, e = part("SYNO.Core.Security.Firewall", r_fw)
    if fw is None:
        add("warning", "firewall_unreadable", "condition", f"cannot read firewall state: {e}")
    elif not fw.get("enable_firewall"):
        add("critical", "firewall_off", "condition", "DSM firewall is OFF")

    # DSM version
    checks += 1
    fwver = sysinfo.get("firmware_ver", "")
    verdict = advisories.dsm_verdict(fwver)
    if verdict.get("status") != "patched":
        add("critical", "dsm_unpatched", "condition",
            f"{fwver}: SA-26:13 {verdict.get('status')}" + (f" ({verdict['note']})" if verdict.get("note") else ""))
    latest = config.get()["latest_dsm"]
    if latest and _version_tuple(fwver) < _version_tuple("DSM " + latest):
        add("warning", "dsm_behind", "condition", f"{fwver} is older than {latest}")
    upd, _ = part("SYNO.Core.Upgrade.Server", r_upd)
    if upd and ((upd.get("update") or {}).get("available") or (upd.get("promotion") or {}).get("available")):
        add("info", "dsm_update_available", "condition", "Synology offers a DSM update (Control Panel → Update & Restore)")

    # storage
    st, e = part("SYNO.Storage.CGI.Storage", r_st)
    disks = (st or {}).get("disks", [])
    if st is None:
        add("warning", "storage_unreadable", "condition", f"cannot read storage state: {e}")
    for d in disks:
        checks += 1
        label = f"{d.get('longName') or d.get('id')} ({(d.get('model') or '').strip()})"
        if d.get("status") != "normal":
            add("warning", "disk_status", "condition", f"{label}: status {d.get('status')}")
        if d.get("smart_status") not in ("normal", None):
            add("warning", "disk_smart", "condition", f"{label}: SMART {d.get('smart_status')}")
    for p in (st or {}).get("storagePools", []):
        checks += 1
        if p.get("status") != "normal":
            add("warning", "pool_status", "condition", f"storage pool {p.get('id')}: {p.get('status')}")
    for v in (st or {}).get("volumes", []):
        checks += 1
        if v.get("status") != "normal":
            add("warning", "volume_status", "condition", f"{v.get('id')}: {v.get('status')}")

    smart = s.call_many([{"api": "SYNO.Storage.CGI.Smart", "method": "get_smart_info", "version": 1,
                          "params": {"device": d.get("device") or f"/dev/{d.get('id')}"}} for d in disks]) if disks else []
    now_disks = {}
    for d, r in zip(disks, smart):
        data, _ = part("SYNO.Storage.CGI.Smart", r)
        now_disks[d.get("serial") or d.get("id")] = {
            "slot": d.get("slot_id"), "name": d.get("longName") or d.get("id"),
            "model": (d.get("model") or "").strip(), "power_cycle": _power_cycles(data)}

    # UPS
    checks += 1
    ups, e = part("SYNO.Core.ExternalDevice.UPS", r_ups)
    if ups is None:
        add("info", "ups_unreadable", "condition", f"cannot read UPS state: {e}")
    elif ups.get("enable"):
        status = str(ups.get("status") or "")
        if "onbatt" in status or "battery" in status:
            add("critical", "ups_on_battery", "condition", f"UPS on battery ({status}, charge {ups.get('charge')}%)")
        elif not status.endswith("online"):
            add("warning", "ups_status", "condition", f"UPS status {status}")
        try:
            if int(ups.get("charge")) < 50:
                add("warning", "ups_charge_low", "condition", f"UPS charge {ups.get('charge')}%")
        except (TypeError, ValueError):
            pass

    # packages outside the configured volume
    pk, _ = part("SYNO.Core.Package", r_pkg)
    vol = config.get()["alert"]["package_volume"].rstrip("/")
    if vol:
        off = [p["id"] for p in (pk or {}).get("packages", [])
               if ((p.get("additional") or {}).get("installed_info") or {}).get("path", "").startswith("/volume")
               and not p["additional"]["installed_info"]["path"].startswith(vol + "/")]
        checks += 1
        if off:
            add("info", "packages_off_volume1", "condition", f"installed outside {vol}: " + ", ".join(off))

    # Tailscale (remote access path; key expiry would cut it)
    if any(p.get("id") == "Tailscale" for p in (pk or {}).get("packages", [])):
        checks += 1
        try:
            ts = s.backend.tailscale_data() if s.backend_name == "local" else _ts_data(s, timeout=20)[0]
        except NasError as e:
            ts = None
            add("warning", "tailscale_unreadable", "condition", f"cannot read Tailscale status: {e}")
        if ts is not None:
            if ts.get("Status") != "Running":
                add("warning", "tailscale_down", "condition", f"Tailscale status {ts.get('Status')}")
            exp = ts.get("KeyExpiry") or ""
            try:
                left = dt.datetime.strptime(exp[:19], "%Y-%m-%dT%H:%M:%S") - dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
            except ValueError:
                left = None
            if ts.get("KeyExpired") or (left is not None and left < dt.timedelta(days=args.key_days)):
                add("warning", "tailscale_key_expiring", "condition", f"Tailscale node key expires {exp}")

    # folders that should keep receiving files (e.g. camera recordings): newest file per folder
    rec = config.get()["alert"]["recordings"]
    if rec["folders"]:
        checks += 1
        rec_root = rec["path"].rstrip("/")
        local_root = rec["local_path"] or ("/volume1" + rec_root)
        now_ts = dt.datetime.now().timestamp()
        for cam in rec["folders"]:
            newest = _newest_recording_local(local_root, cam) if s.backend_name == "local" else None
            hours = {} if s.backend_name == "local" else s.call(
                "SYNO.FileStation.List", "list", {"folder_path": f"{rec_root}/{cam}", "sort_by": "name",
                                                  "sort_direction": "desc", "limit": 3}, version=2)
            for h in ((hours.get("data") or {}).get("files") or [] if hours.get("ok") else []):
                files = s.call("SYNO.FileStation.List", "list", {"folder_path": h["path"], "sort_by": "mtime",
                                                                 "sort_direction": "desc", "limit": 1,
                                                                 "additional": ["time"]}, version=2)
                fl = (files.get("data") or {}).get("files") or [] if files.get("ok") else []
                if fl:
                    newest = (fl[0].get("additional") or {}).get("time", {}).get("mtime")
                    break
            if newest is None or now_ts - newest > rec["max_age_min"] * 60:
                age = "no recordings" if newest is None else f"last file {int((now_ts - newest) // 60)} min ago"
                note = f" ({rec['note']})" if rec["note"] else ""
                add("warning", "camera_recording_stale", "condition", f"{cam}: {age}{note}")

    # scheduled snapshots: newest scheduled snapshot per share should be recent
    try:
        nas_clock = dt.datetime.strptime(sysinfo["time"], "%Y-%m-%d %H:%M:%S")
    except (KeyError, ValueError):
        nas_clock = dt.datetime.now()
    shares = config.get()["snapshot_shares"]
    max_age = dt.timedelta(hours=config.get()["snapshot_max_age_hours"])
    snap = snapshot_state(s, shares) if shares else {"shares": {}}
    for share in shares:
        checks += 1
        st_ = snap["shares"][share]
        if st_["schedule"] is None:
            add("warning", "snapshot_unreadable", "condition", f"{share}: cannot read snapshot schedule: {st_['error']}")
            continue
        if not st_["enabled"]:
            add("warning", "snapshot_schedule_off", "condition", f"{share}: scheduled snapshots are off (Snapshot Replication)")
            continue
        # models without immutable snapshots: with the lock on, scheduled snapshots fail without a log entry
        if snap["worm_supported"] is False and (st_["worm"] or {}).get("worm_lock_enable"):
            add("warning", "snapshot_worm_unsupported", "condition",
                f"{share}: immutable snapshots are on but this model does not support them, so scheduled snapshots are not taken")
        newest = st_["newest"]
        if newest is None or nas_clock - newest > max_age:
            last = "none yet" if newest is None else f"{newest:%Y-%m-%d %H:%M}"
            add("warning", "snapshot_stale", "condition",
                f"{share}: no scheduled snapshot in the last {config.get()['snapshot_max_age_hours']} h (newest: {last})")

    # state: power cycles, missing disks, log cursor
    state = _load_state(args.state)
    boot = _boot_time(sysinfo)
    first_run = state is None
    if first_run:
        state = {"created": sysinfo.get("time"), "boot_time": boot, "disks": {}, "last_log_time": None}
    rebooted = bool(boot and state.get("boot_time") and boot != state.get("boot_time"))
    for key, cur in now_disks.items():
        checks += 1
        prev = state["disks"].get(key)
        if prev and cur["power_cycle"] is not None and prev.get("power_cycle") is not None:
            delta = cur["power_cycle"] - prev["power_cycle"]
            if delta > (1 if rebooted else 0):
                add("warning", "disk_power_cycled", "event",
                    f"{cur['name']} ({cur['model']}) power-cycled {delta}× since the last check "
                    f"(NAS {'rebooted once' if rebooted else 'did not reboot'}): drive lost power in its bay")
    for key, prev in state["disks"].items():
        if key not in now_disks:
            add("warning", "disk_missing", "event", f"{prev.get('name')} ({prev.get('model')}) is no longer detected")
    if rebooted:
        add("info", "nas_rebooted", "event", f"NAS booted at {boot} (previous boot {state.get('boot_time')})")

    # connection log
    checks += 1
    try:
        nas_now = dt.datetime.strptime(sysinfo["time"], "%Y-%m-%d %H:%M:%S")
    except (KeyError, ValueError):
        nas_now = dt.datetime.now()
    if args.since:
        since = args.since.strip().replace("-", "/")
    else:
        since = (nas_now - dt.timedelta(minutes=args.window)).strftime("%Y/%m/%d %H:%M:%S")
    items, _ = fetch_connection_log(s, since, args.log_limit)
    failed = [x for x in items if "fail" in (x.get("descr") or "")]
    if len(failed) > args.failed_threshold:
        ips = {_ip_of((_LOG_FROM.search(x.get("descr", "")) or [None, ""])[1]) for x in failed}
        add("warning", "failed_signins", "condition",
            f"{len(failed)} failed sign-ins since {since} from {len(ips)} IPs (threshold {args.failed_threshold})")
    cursor = state.get("last_log_time")
    for x in items:
        descr = x.get("descr") or ""
        if "fail" in descr or not ("signed in" in descr or "logged in" in descr):
            continue
        if cursor and (x.get("time") or "") <= cursor:
            continue
        ip = _ip_of((_LOG_FROM.search(descr) or [None, ""])[1])
        if not _allowed(ip):
            user = (_LOG_USER.search(descr) or [None, "?"])[1]
            via = (_LOG_VIA.search(descr) or [None, "?"])[1]
            add("critical", "external_signin", "event", f"{x.get('time')} {user} signed in from {ip} via {via}")
    newest = max((x.get("time") or "" for x in items), default=None)

    pushed = push(findings, args, sysinfo.get("time")) if args.push else None

    if not args.no_update:
        state["boot_time"] = boot or state.get("boot_time")
        state["disks"] = now_disks
        state["last_log_time"] = max(filter(None, [cursor, newest]), default=None)
        state["updated"] = sysinfo.get("time")
        _save_state(args.state, state)

    bad = [f for f in findings if f["level"] in ("critical", "warning")]
    order = {"critical": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: order[f["level"]])
    lines = [f"{f['level'].upper():<8} {f['code']}: {f['message']}" for f in findings]
    if first_run:
        lines.append(f"(new baseline written to {args.state})" if not args.no_update else "(no baseline yet; --no-update)")
    if not bad:
        lines.insert(0, f"OK — nothing at warning/critical level ({checks} checks)")
    if pushed:
        lines.append(pushed)
    # --json prints the findings list itself (empty list = all clear)
    return lines, findings, (1 if bad else 0)


# --- --push: send what changed to a webhook (any HTTPS endpoint + one header) ---

# Codes whose message starts with "<subject>:" (camera, disk, share, pool, volume): each
# subject is tracked on its own, so a second camera going stale is news too.
_SUBJECT_CODES = {"camera_recording_stale", "disk_status", "disk_smart", "pool_status", "volume_status",
                  "snapshot_stale", "snapshot_schedule_off", "snapshot_worm_unsupported", "snapshot_unreadable"}


def _key(f: dict) -> str:
    if f["code"] in _SUBJECT_CODES and ":" in f["message"]:
        return f"{f['code']}:{f['message'].split(':', 1)[0]}"
    return f["code"]


def _sent_at(entry) -> dt.datetime:
    try:
        return dt.datetime.fromisoformat(entry["sent"])
    except (TypeError, KeyError, ValueError):
        return dt.datetime.min


def _push_config(args) -> tuple[dict, str]:
    try:
        with open(args.push, encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, ValueError) as e:
        raise NasError(f"--push {args.push}: {e}")
    if not cfg.get("url") or ":" not in (cfg.get("header") or ""):
        raise NasError(f'--push {args.push}: needs "url" and "header" ("Name: value", e.g. "Authorization: Bearer ...")')
    u = urllib.parse.urlsplit(cfg["url"])
    if u.scheme != "https" and not (u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost", "::1")):
        raise NasError(f"--push {args.push}: the URL must be https:// (the header is a secret); "
                       "http:// is accepted only for 127.0.0.1/localhost")
    return cfg, os.path.splitext(args.state)[0] + "-pushed.json"


def _load_push_state(path: str) -> dict:
    """An unreadable push state is moved aside (…-pushed.json.corrupt) instead of stopping every later push."""
    try:
        st = _load_state(path)
    except NasError:
        os.replace(path, path + ".corrupt")
        st = None
    if not isinstance(st, dict):
        return {"active": {}, "pending_events": []}
    if not isinstance(st.get("active"), dict):
        st["active"] = {}
    st["pending_events"] = [e for e in st.get("pending_events") or [] if isinstance(e, dict)][-PUSH_PENDING_MAX:]
    return st


def _post(cfg: dict, body: dict) -> str | None:
    """None on HTTP 200 (run accepted), else a short reason. The header value is never echoed."""
    name, value = cfg["header"].split(":", 1)
    req = urllib.request.Request(cfg["url"], json.dumps(body, ensure_ascii=False).encode(),
                                 {"Content-Type": "application/json", name.strip(): value.strip()})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return None if r.status == 200 else f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}"
    except (urllib.error.URLError, OSError) as e:
        return str(getattr(e, "reason", e))


def _body(nas_time, findings, resolved, active, heartbeat=False) -> dict:
    order = {"critical": 0, "warning": 1, "info": 2}
    return {"source": "nas-alert", "host": config.get()["name"], "time": nas_time, "heartbeat": heartbeat,
            "findings": sorted(findings, key=lambda f: order.get(f.get("level"), 3)),
            "resolved": resolved, "still_active": sorted(active)}


def push(findings: list[dict], args, nas_time: str | None) -> str:
    """POST only what changed since the last successful push.

    Sent: conditions that are new (per code, or per code + subject for
    _SUBJECT_CODES), warning/critical conditions still there after
    PUSH_REMIND ("repeat": true), every event, and keys that cleared
    ("resolved"). The first run at or after HEARTBEAT_HOUR each day sends
    something even if nothing changed ("heartbeat": true when that is all it
    is), so silence for a day means the check is not running. A failed POST
    leaves the conditions as they were and keeps the events in
    "pending_events", so the next run sends the same news again.
    """
    cfg, path = _push_config(args)
    st = _load_push_state(path)
    active, pending, last_hb = st["active"], st["pending_events"], st.get("heartbeat") or ""
    now = dt.datetime.now()
    stamp = now.isoformat(timespec="seconds")
    cur: dict[str, dict] = {}
    for f in findings:
        if f["kind"] == "condition":
            cur.setdefault(_key(f), f)
    send, sent = [], set()
    for k, f in cur.items():
        # state written before per-subject keys has the bare code: treat it as this subject's entry
        prev = active.get(k) or (active.get(f["code"]) if f["code"] in _SUBJECT_CODES else None)
        if prev is None or (f["level"] in ("critical", "warning") and now - _sent_at(prev) >= PUSH_REMIND):
            send.append(dict(f, repeat=prev is not None))
            sent.add(k)
    events = pending + [f for f in findings if f["kind"] == "event"]
    send += events
    resolved = sorted(k for k in active if k not in cur
                      and not (k in _SUBJECT_CODES and any(c.startswith(k + ":") for c in cur)))
    new_active = {k: {"level": f["level"],
                      "sent": stamp if k in sent else ((active.get(k) or active.get(f["code"]) or {}).get("sent") or stamp)}
                  for k, f in cur.items()}
    heartbeat_due = now.hour >= HEARTBEAT_HOUR and last_hb[:10] != now.strftime("%Y-%m-%d")
    if not send and not resolved and not heartbeat_due:
        if st.get("failures") or set(new_active) != set(active):
            _save_state(path, {"active": new_active, "failures": 0, "pending_events": [], "heartbeat": last_hb})
        return "push: nothing new"
    err = _post(cfg, _body(nas_time, send, resolved, cur, heartbeat=not send and not resolved))
    if err:
        _save_state(path, {**st, "pending_events": events[-PUSH_PENDING_MAX:]})
        return f"push: FAILED ({err}); will resend next run"
    _save_state(path, {"active": new_active, "failures": 0, "pending_events": [], "heartbeat": stamp})
    if not send and not resolved:
        return "push: sent heartbeat"
    return f"push: sent {len(send)} finding(s), {len(resolved)} resolved"


def push_failure(args, error: str) -> str:
    """The check itself failed (synowebapi, login, a crash): send "alert_failed" after PUSH_FAIL_AFTER runs in a row."""
    cfg, path = _push_config(args)
    st = _load_push_state(path)
    active = st["active"]
    failures = int(st.get("failures") or 0) + 1
    now = dt.datetime.now()
    prev = active.get("alert_failed")
    msg = (f"push: not sent yet (failure {failures} of {PUSH_FAIL_AFTER})" if failures < PUSH_FAIL_AFTER
           else f"push: alert_failed already sent ({failures} failures in a row)")
    if failures >= PUSH_FAIL_AFTER and (prev is None or now - _sent_at(prev) >= PUSH_REMIND):
        f = {"level": "warning", "code": "alert_failed", "kind": "condition", "repeat": prev is not None,
             "message": f"nas alert failed {failures} runs in a row: {error}"[:500]}
        err = _post(cfg, _body(now.strftime("%Y-%m-%d %H:%M:%S"), [f], [], set(active) | {"alert_failed"}))
        if err:
            msg = f"push: FAILED ({err})"
        else:
            active["alert_failed"] = {"level": "warning", "sent": now.isoformat(timespec="seconds")}
            msg = "push: sent alert_failed"
    _save_state(path, {**st, "active": active, "failures": failures})
    return msg
