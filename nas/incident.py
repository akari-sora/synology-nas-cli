"""`nas incident`: audit a DSM box against the C3RB3R / .L0CK3D ransomware campaign
(Synology-SA-26:13, SA-26:14), and `nas incident fix`: apply the hardening in one go.

Audit (read-only): every item is PASS / WARN / FAIL / SKIP with a one-line hint;
exit status 1 when any item is FAIL. --probe opens TCP connections to the public
address, --scan runs a File Station search for ransom notes.

Fix: audit -> plan (each change, current -> new, and the exact API calls) ->
confirmation (or --yes) -> apply in a fixed order -> read each change back ->
audit again and print before/after. --dry-run prints the plan and the calls
without sending any write. The firewall change refuses to run when the address
this CLI connects from would not be allowed, and verifies a fresh login over the
same origin after applying it.
"""

from __future__ import annotations

import copy
import datetime as dt
import ipaddress
import json
import secrets
import shlex
import socket
import string
import sys
import time
import types
import urllib.parse
import urllib.request

from . import advisories, config
from .alert import _allowed, allowed_networks
from .backends import NasError, PasswordBackend, describe_error
from .errors import InputRequired, can_prompt
from .commands import (PORTS, _ip_of, fetch_connection_log, is_read_method, list_shares, need, part,
                       probe_ports, public_addresses, ransom_scan, snapshot_state)
from .commands import _LOG_FROM, _LOG_USER, _LOG_VIA

PASS, WARN, FAIL, SKIP = "PASS", "WARN", "FAIL", "SKIP"

# Proxy lookups, replaceable in tests (urllib also reads the macOS system proxy settings).
get_proxies = urllib.request.getproxies
proxy_bypass = urllib.request.proxy_bypass

# Order `incident fix` applies changes in: data protection first, the firewall (lockout risk) last
# of the default set, then the opt-in ones (the DSM upgrade reboots the NAS, so it goes at the very end).
FIX_ORDER = ["snapshot_worm", "snapshots", "packages", "smb_min_protocol", "quickconnect",
             "router_port_forwarding", "autoblock", "admin_account", "firewall", "rotate_password", "upgrade"]
OPT_IN = {"rotate_password": "--rotate-password", "upgrade": "--upgrade"}

# Where each fix lives in the DSM web UI (English, 繁體中文).
UI = {
    "firewall": ("Control Panel > Security > Firewall: tick Enable firewall, Edit Rules: allow your LAN/VPN "
                 "ranges, set 'If no rules are matched' to Deny for every interface",
                 "控制台 > 安全性 > 防火牆：啟動防火牆，編輯規則"),
    "quickconnect": ("Control Panel > External Access > QuickConnect: untick Enable QuickConnect "
                     "(Advanced: untick automatic port forwarding)",
                     "控制台 > 外部存取 > QuickConnect"),
    "router_port_forwarding": ("Control Panel > External Access > Router Configuration: disable or delete the rules "
                               "(also check the router's own UPnP / port-forwarding page)",
                               "控制台 > 外部存取 > 路由器設定"),
    "smb_min_protocol": ("Control Panel > File Services > SMB > Advanced Settings > General: minimum SMB protocol SMB2",
                         "控制台 > 檔案服務 > SMB > 進階設定"),
    "autoblock": ("Control Panel > Security > Protection > Auto Block: enable; Allow/Block List > Allow List",
                  "控制台 > 安全性 > 保護 > 自動封鎖；允許/封鎖清單"),
    "admin_account": ("Control Panel > User & Group > User > admin > Edit: Disable this account",
                      "控制台 > 使用者與群組 > 使用者 > admin > 編輯"),
    "snapshots": ("Snapshot Replication > Snapshots > select the shared folder > Settings > Schedule and "
                  "Retention Policy", "Snapshot Replication > 快照 > 選取共用資料夾 > 設定 > 排程／保留原則"),
    "snapshot_worm": ("Snapshot Replication > Snapshots > Settings > immutable snapshots (the UI hides the option on "
                      "models without support; there the API call is the only way)",
                      "Snapshot Replication > 快照 > 設定（不支援的機型不顯示此選項）"),
    "packages": ("Package Center > Installed > the package: Update, or Stop / Uninstall",
                 "套件中心 > 已安裝 > 該套件：更新，或停止／解除安裝"),
    "upgrade": ("Control Panel > Update & Restore > DSM Update > Manual DSM Update",
                "控制台 > 更新與還原 > DSM 更新 > 手動更新 DSM"),
    "rotate_password": ("top-right person icon > Personal > Account > change password; then update your password store",
                        "右上角人像 > 個人 > 帳號 > 變更密碼"),
}

RESCUE = """If this computer can no longer reach DSM after the firewall change:
  - From a computer whose address the allow-list covers (same LAN as the NAS), open https://<NAS LAN IP>:5001
    and fix or disable the firewall: Control Panel > Security > Firewall (控制台 > 安全性 > 防火牆).
  - Synology Assistant (desktop app) or https://find.synology.com finds the NAS on its LAN.
  - Tailscale's DSM package in userspace mode (its default) reaches DSM as 127.0.0.1, which the DSM firewall
    did not filter in testing; a tailnet device may still get in.
  - Last resort at the NAS: hold RESET about 4 s until one beep ("mode 1"). Synology's article "How do I reset
    my Synology NAS?" lists what that resets for your DSM version (network settings and the admin password)."""


def item(id_, status, detail, hint="", fix=None) -> dict:
    return {"id": id_, "status": status, "detail": detail, "hint": hint, "fix": fix}


# --- gather (read-only) -----------------------------------------------------------------------------------

_READS = [
    ("sys", "SYNO.Core.System", "info", 1, None),
    ("pkgs", "SYNO.Core.Package", "list", 1, {"additional": ["status"]}),
    ("fw", "SYNO.Core.Security.Firewall", "get", None, None),
    ("ppp", "SYNO.Core.Network.PPPoE", "list", None, None),
    ("ifaces", "SYNO.Core.Network.Interface", "list", None, None),
    ("qc", "SYNO.Core.QuickConnect", "get", None, None),
    ("qc_upnp", "SYNO.Core.QuickConnect.Upnp", "get", 1, None),
    ("autoblock", "SYNO.Core.Security.AutoBlock", "get", None, None),
    ("smb", "SYNO.Core.FileServ.SMB", "get", None, None),
    ("users", "SYNO.Core.User", "list", 1, {"type": "local", "offset": 0, "limit": -1, "additional": ["expired"]}),
    ("admins", "SYNO.Core.Group.Member", "list", 1, {"group": "administrators", "ingroup": True, "offset": 0,
                                                     "limit": -1}),
    ("pf", "SYNO.Core.PortForwarding.Rules", "load", 1, None),
    ("dsm_web", "SYNO.Core.Web.DSM", "get", None, None),
]


def gather(s, args) -> dict:
    res = s.call_many([{"api": api, "method": m, "version": v, "params": p} for _, api, m, v, p in _READS])
    f = {k: part(api, r) for (k, api, _, _, _), r in zip(_READS, res)}
    fw, _ = f["fw"]
    f["fw_profile"], f["fw_adapters"] = (None, "firewall unreadable"), (None, "firewall unreadable")
    if fw is not None and fw.get("profile_name"):
        r_prof, r_ad = s.call_many([
            {"api": "SYNO.Core.Security.Firewall.Profile", "method": "get", "version": 1,
             "params": {"name": fw["profile_name"]}},
            {"api": "SYNO.Core.Security.Firewall.Adapter", "method": "list", "version": 1,
             "params": {"profile_name": fw["profile_name"]}},
        ])
        f["fw_profile"] = part("SYNO.Core.Security.Firewall.Profile", r_prof)
        f["fw_adapters"] = part("SYNO.Core.Security.Firewall.Adapter", r_ad)
    try:
        f["log"] = (fetch_connection_log(s, None, args.log_limit)[0], None)
    except NasError as e:
        f["log"] = (None, str(e))
    shares = list(config.get()["snapshot_shares"])
    f["shares_configured"] = bool(shares)
    if not shares:
        try:
            shares = list_shares(s)
        except NasError as e:
            f["shares_error"] = str(e)
    f["shares"] = shares
    f["snap"] = snapshot_state(s, shares) if shares else None
    f["probe"] = _probe(s, args, f) if getattr(args, "probe", False) else None
    f["scan"] = None
    if getattr(args, "scan", False):
        try:
            f["scan"] = (ransom_scan(s, types.SimpleNamespace(pattern=None, timeout=args.scan_timeout))[1], None)
        except NasError as e:
            f["scan"] = (None, str(e))
    return f


def _probe(s, args, f) -> dict:
    if s.backend_name == "local":
        return {"skip": "--backend local runs on the NAS itself; probe from another machine"}
    pub4, pub6, source = public_addresses(s)
    if not pub4 and not pub6:
        return {"skip": "public address unknown (the NAS does not dial PPPoE; set public_ip in the config)"}
    web, _ = f["dsm_web"]
    dsm_ports = {int((web or {}).get("http_port") or 5000), int((web or {}).get("https_port") or 5001)}
    ports = dict(PORTS)
    for p in dsm_ports:
        ports.setdefault(p, "DSM")
    targets = ([("public v4", pub4)] if pub4 else []) + ([("public v6", pub6)] if pub6 else [])
    res = probe_ports(targets, ports, args.probe_timeout)
    open_ = sorted({(port, ports[port]) for (lbl, port), v in res.items() if v == "OPEN"})
    return {"targets": dict(targets), "source": source, "dsm_ports": sorted(dsm_ports), "open": open_}


# --- evaluate -----------------------------------------------------------------------------------------------

def _nas_public(f) -> list:
    out = []
    for p in (f["ppp"][0] or []):
        if p.get("status") == "connected" and p.get("ip"):
            out.append(p["ip"])
    for i in (f["ifaces"][0] or []):
        try:
            if i.get("ip") and ipaddress.ip_address(i["ip"]).is_global and i["ip"] not in out:
                out.append(i["ip"])
        except ValueError:
            pass
    return out


def _adapters(f) -> list:
    ad, _ = f["fw_adapters"]
    prof, _ = f["fw_profile"]
    names = list((ad or {}).get("adapter_names") or [])
    for k, v in (prof or {}).items():
        if isinstance(v, dict) and k not in names:
            names.append(k)
    return names


def _allow_all_rules(prof: dict) -> list:
    out = []
    for a, v in (prof or {}).items():
        if not isinstance(v, dict):
            continue
        for r in v.get("rules") or []:
            if r.get("enable", True) and r.get("policy") == "allow" and r.get("source_ip") == "all":
                out.append((a, r.get("ports")))
    return out


def _pf_rules(data) -> list | None:
    """Rules from SYNO.Core.PortForwarding.Rules load, or None when the shape is not recognised."""
    if isinstance(data, list):
        rules = data
    elif isinstance(data, dict):
        rules = data.get("rules") if isinstance(data.get("rules"), list) else None
        if rules is None:
            return None
    else:
        return None
    return [r for r in rules if isinstance(r, dict)]


def _nas_now(f) -> dt.datetime:
    try:
        return dt.datetime.strptime((f["sys"][0] or {})["time"], "%Y-%m-%d %H:%M:%S")
    except (KeyError, TypeError, ValueError):
        return dt.datetime.now()


def evaluate(f, args) -> list:
    items = []
    add = items.append
    sysinfo, e_sys = f["sys"]

    # 1. DSM build vs SA-26:13
    if sysinfo is None:
        add(item("dsm_version", SKIP, f"cannot read DSM version: {e_sys}"))
    else:
        fw_ver = sysinfo.get("firmware_ver", "")
        v = advisories.dsm_verdict(fw_ver)
        if v["status"] == "patched":
            add(item("dsm_version", PASS, f"{fw_ver}: SA-26:13 patched (fixed in {v['fixed_in']})"))
        elif v["status"] == "unknown":
            add(item("dsm_version", WARN, v["note"], "check Control Panel > Update & Restore"))
        else:
            add(item("dsm_version", FAIL, f"{fw_ver}: SA-26:13 {v['status']}. {v.get('note', '')}".strip(),
                     "nas upgrade --dry-run, then `nas incident fix --upgrade` (the NAS reboots)", "upgrade"))

    # 2. SA-26:14 packages
    pk, e = f["pkgs"]
    if pk is None:
        add(item("sa_26_14_packages", SKIP, f"cannot list packages: {e}"))
    else:
        running, stopped, ok = [], [], []
        for p in pk.get("packages", []):
            verdict = advisories.package_verdict(p.get("id"), p.get("version", ""))
            if verdict is None:
                continue
            status = (p.get("additional") or {}).get("status")
            label = f"{p.get('id')} {p.get('version')} ({status})"
            if verdict["status"] == "patched":
                ok.append(label)
            else:
                (running if status == "running" else stopped).append(label)
        if running:
            add(item("sa_26_14_packages", FAIL, "vulnerable to SA-26:14 and running: " + ", ".join(running + stopped),
                     "update in Package Center, or stop/uninstall; `nas incident fix` stops running ones", "packages"))
        elif stopped:
            add(item("sa_26_14_packages", WARN, "vulnerable to SA-26:14, stopped: " + ", ".join(stopped),
                     "update in Package Center (or uninstall) before starting it again"))
        else:
            add(item("sa_26_14_packages", PASS, ("patched: " + ", ".join(ok)) if ok else
                     "none of Calendar, MailStation, PHP 7.3-8.4 installed"))

    # 3. firewall
    fw, e = f["fw"]
    prof, _ = f["fw_profile"]
    public = _nas_public(f)
    if fw is None:
        add(item("firewall", SKIP, f"cannot read firewall: {e}"))
    elif not fw.get("enable_firewall"):
        if public:
            add(item("firewall", FAIL, f"firewall OFF and the NAS holds public address {', '.join(public)}: "
                     "every DSM service is reachable from the internet", "nas incident fix --only firewall", "firewall"))
        else:
            add(item("firewall", WARN, "firewall OFF (no public address on the NAS itself; the router's port "
                     "forwards decide what is reachable)", "nas incident fix --only firewall", "firewall"))
    else:
        open_ad = [a for a in _adapters(f) if a != "global" and ((prof or {}).get(a) or {}).get("policy") != "drop"]
        any_rules = _allow_all_rules(prof)
        if prof is None:
            add(item("firewall", PASS, f"on (profile {fw.get('profile_name')}); rules not readable"))
        elif open_ad or any_rules:
            why = []
            if open_ad:
                why.append("interfaces that allow unmatched traffic: " + ", ".join(open_ad))
            if any_rules:
                why.append("rules that allow any source: " + ", ".join(f"{a} ports {p}" for a, p in any_rules))
            add(item("firewall", FAIL if public else WARN, f"on (profile {fw.get('profile_name')}) but " + "; ".join(why),
                     "nas incident fix --only firewall", "firewall"))
        else:
            add(item("firewall", PASS, f"on (profile {fw.get('profile_name')}), unmatched traffic dropped on every interface"))

    # 4. QuickConnect (+ its UPnP port forwarding)
    qc, e = f["qc"]
    upnp, _ = f["qc_upnp"]
    if qc is None:
        add(item("quickconnect", SKIP, f"cannot read QuickConnect: {e}"))
    elif qc.get("enabled"):
        bits = [f"QuickConnect ON (id {qc.get('server_alias') or '-'}): Synology's relay reaches the DSM login page"]
        if (upnp or {}).get("enabled"):
            bits.append("its automatic router port forwarding is on too")
        add(item("quickconnect", WARN, "; ".join(bits), "nas incident fix --only quickconnect", "quickconnect"))
    else:
        add(item("quickconnect", PASS, "QuickConnect off" + (
            " (its automatic port-forwarding setting is still on; `incident fix` turns it off; router rules are "
            "checked under router_port_forwarding)" if (upnp or {}).get("enabled") else "")))

    # 5. router port forwarding rules DSM created (UPnP / NAT-PMP)
    pf, e = f["pf"]
    rules = _pf_rules(pf) if pf is not None else None
    if pf is None:
        add(item("router_port_forwarding", SKIP, f"no router configured in DSM or not readable ({e})"))
    elif rules is None:
        add(item("router_port_forwarding", SKIP, "unrecognised SYNO.Core.PortForwarding.Rules load response"))
    else:
        on = [r for r in rules if r.get("enable")]
        if on:
            ports = ", ".join(f"{r.get('router_port')}->{r.get('ds_port')}" for r in on)
            add(item("router_port_forwarding", WARN, f"DSM keeps {len(on)} enabled router port-forwarding rule(s): {ports}",
                     "nas incident fix --only router_port_forwarding", "router_port_forwarding"))
        else:
            add(item("router_port_forwarding", PASS, "no enabled router port-forwarding rules in DSM"))

    # 6. DSM / service ports reachable on the public address
    pr = f["probe"]
    if pr is None:
        add(item("public_ports", SKIP, "pass --probe to test the public address from this machine (opens TCP connections)"))
    elif pr.get("skip"):
        add(item("public_ports", SKIP, pr["skip"]))
    else:
        dsm_open = [f"{p} {n}" for p, n in pr["open"] if p in pr["dsm_ports"]]
        other = [f"{p} {n}" for p, n in pr["open"] if p not in pr["dsm_ports"]]
        where = ", ".join(f"{k} {v}" for k, v in pr["targets"].items())
        note = "probed from this machine; through your own router this is a hint, confirm from outside"
        if dsm_open:
            add(item("public_ports", FAIL, f"DSM reachable on {where}: {', '.join(dsm_open + other)} ({note})",
                     "nas incident fix --only firewall; remove router port forwards", "firewall"))
        elif other:
            add(item("public_ports", WARN, f"open on {where}: {', '.join(other)} ({note})",
                     "nas incident fix --only firewall; remove router port forwards", "firewall"))
        else:
            add(item("public_ports", PASS, f"no tested port open on {where} ({note})"))

    # 7/8. sign-ins
    log, e = f["log"]
    if log is None:
        add(item("external_signins", SKIP, f"cannot read the connection log: {e}"))
        add(item("failed_signins", SKIP, f"cannot read the connection log: {e}"))
    else:
        nets = allowed_networks()
        ext, failed, fail_ips, last_fail = {}, 0, set(), ""
        since = (_nas_now(f) - dt.timedelta(hours=args.hours)).strftime("%Y/%m/%d %H:%M:%S")
        for x in log:
            descr = x.get("descr") or ""
            ip = _ip_of((_LOG_FROM.search(descr) or [None, ""])[1])
            if "fail" in descr:
                if (x.get("time") or "") >= since:
                    failed += 1
                    fail_ips.add(ip)
                    last_fail = max(last_fail, x.get("time") or "")
            elif ("signed in" in descr or "logged in" in descr) and not _allowed(ip, nets):
                user = (_LOG_USER.search(descr) or [None, "?"])[1]
                via = (_LOG_VIA.search(descr) or [None, "?"])[1]
                e = ext.setdefault((user, ip, via), {"n": 0, "last": ""})
                e["n"] += 1
                e["last"] = max(e["last"], x.get("time") or "")
        times = sorted(x.get("time") or "" for x in log)
        span = f"{times[0]} .. {times[-1]}" if times else "empty log"
        if ext:
            rows = sorted(ext.items(), key=lambda kv: kv[1]["last"], reverse=True)
            text = "; ".join(f"{u} from {ip} via {via} x{e['n']} (last {e['last']})" for (u, ip, via), e in rows[:5])
            add(item("external_signins", FAIL, f"{sum(e['n'] for e in ext.values())} successful sign-in(s) from outside "
                     f"allowed_networks in the log ({span}): " + text + (" ..." if len(rows) > 5 else ""),
                     "if any is not you: change that account's password (`nas incident fix --rotate-password` for "
                     "this one), check users/tasks/packages, follow docs/INCIDENT-C3RB3R.md"))
        else:
            add(item("external_signins", PASS, f"none in {len(log)} log entries ({span})"))
        if failed > args.failed_threshold:
            add(item("failed_signins", WARN, f"{failed} failed sign-ins in the last {args.hours} h from "
                     f"{len(fail_ips)} address(es), latest {last_fail}", "someone is guessing passwords: close the exposure (firewall, "
                     "router port forwards, QuickConnect) and keep AutoBlock on", "firewall"))
        else:
            add(item("failed_signins", PASS, f"{failed} failed sign-ins in the last {args.hours} h"))

    # 9. AutoBlock
    ab, e = f["autoblock"]
    if ab is None:
        add(item("autoblock", SKIP, f"cannot read AutoBlock: {e}"))
    elif not ab.get("enable"):
        add(item("autoblock", WARN, "AutoBlock off: unlimited password guessing", "nas incident fix --only autoblock",
                 "autoblock"))
    else:
        add(item("autoblock", PASS, f"on: {ab.get('attempts')} attempts in {ab.get('within_mins')} min, "
                 f"block expires after {ab.get('expire_day')} day(s) (0 = never)"))

    # 10. SMB minimum protocol
    smb, e = f["smb"]
    if smb is None:
        add(item("smb_min_protocol", SKIP, f"cannot read SMB settings: {e}"))
    elif smb.get("smb_min_protocol") == 0:
        state = "on" if smb.get("enable_samba") else "off (setting still SMB1)"
        add(item("smb_min_protocol", FAIL if smb.get("enable_samba") else WARN,
                 f"SMB1 allowed (SMB service {state})", "nas incident fix --only smb_min_protocol; SMB1-only "
                 "clients (old cameras, printers, Windows XP) lose access", "smb_min_protocol"))
    else:
        add(item("smb_min_protocol", PASS, f"minimum SMB protocol {smb.get('smb_min_protocol')} (1 = SMB2)"
                 + ("" if smb.get("enable_samba") else ", SMB service off")))

    # 11. built-in admin
    us, e = f["users"]
    if us is None:
        add(item("admin_account", SKIP, f"cannot list users: {e}"))
    else:
        admin = next((u for u in us.get("users", []) if u.get("name") == "admin"), None)
        if admin is None:
            add(item("admin_account", PASS, "no account named admin"))
        elif admin.get("expired") == "now":
            add(item("admin_account", PASS, "built-in admin is disabled"))
        else:
            add(item("admin_account", WARN, f"built-in admin is enabled (expired={admin.get('expired')}); "
                     "it is the first name password-guessers try", "nas incident fix --only admin_account",
                     "admin_account"))

    # 12/13. snapshots per share
    snap = f["snap"]
    if snap is None:
        add(item("snapshots", SKIP, f"no shares to check ({f.get('shares_error') or 'none found'})"))
    else:
        now = _nas_now(f)
        max_age = dt.timedelta(hours=config.get()["snapshot_max_age_hours"])
        for share in f["shares"]:
            st = snap["shares"][share]
            sid = f"snapshot_schedule:{share}"
            if st["schedule"] is None:
                add(item(sid, SKIP, f"cannot read the schedule ({st['error']}); snapshots need a Btrfs volume "
                         "and Snapshot Replication"))
            elif not st["enabled"]:
                again = st["task_id"] not in (None, -1)
                add(item(sid, WARN, "scheduled snapshots off" + (" (a disabled schedule exists)" if again else
                         " (no schedule)"), "nas incident fix --only snapshots", "snapshots"))
            elif st["newest"] is None or now - st["newest"] > max_age:
                last = "none yet" if st["newest"] is None else f"{st['newest']:%Y-%m-%d %H:%M}"
                add(item(sid, WARN, f"schedule on, but no scheduled snapshot in {config.get()['snapshot_max_age_hours']} h "
                         f"(newest: {last})", "check Snapshot Replication logs; immutable-snapshot lock below"))
            else:
                add(item(sid, PASS, f"scheduled, newest {st['newest']:%Y-%m-%d %H:%M}"))
            wid = f"snapshot_worm:{share}"
            if st["schedule"] is None:
                continue
            if snap["worm_supported"] is None:
                add(item(wid, SKIP, f"cannot read SYNO.DisasterRecovery.Retention info ({snap['retention_error']})"))
            elif st["worm"] is None:
                add(item(wid, SKIP, f"cannot read the immutable-snapshot lock ({st['worm_error']})"))
            elif not snap["worm_supported"] and st["worm"].get("worm_lock_enable"):
                add(item(wid, FAIL, "immutable-snapshot lock ON on a model without immutable snapshots: DSM accepts it "
                         "and scheduled snapshots then silently stop", "nas incident fix --only snapshot_worm",
                         "snapshot_worm"))
            elif not snap["worm_supported"]:
                add(item(wid, PASS, "model has no immutable snapshots; lock off as it must be"))
            elif st["worm"].get("worm_lock_enable"):
                add(item(wid, PASS, f"immutable snapshots on ({st['worm'].get('worm_lock_day')} days)"))
            else:
                add(item(wid, PASS, "immutable snapshots available but off (Snapshot Replication > Settings)"))

    # 14. ransom notes / encrypted files
    sc = f["scan"]
    if sc is None:
        add(item("ransomware_files", SKIP, "pass --scan to search every share for *.L0CK3D / read-me3.txt (minutes)"))
    elif sc[0] is None:
        add(item("ransomware_files", SKIP, f"scan failed: {sc[1]}"))
    else:
        d = sc[0]
        hits = d["root_hits"] + d["search_hits"]
        if hits:
            add(item("ransomware_files", FAIL, f"{len(hits)} hit(s), e.g. {', '.join(hits[:3])}",
                     "isolate the NAS now (unplug WAN / disable port forwards); keep the notes; see "
                     "docs/INCIDENT-C3RB3R.md"))
        elif d["finished"]:
            add(item("ransomware_files", PASS, f"no ransom notes or .L0CK3D files in {len(d['shares'])} share(s)"))
        else:
            add(item("ransomware_files", WARN, "search did not finish (raise --scan-timeout)"))
    return items


def _summary(items) -> dict:
    out = {PASS: 0, WARN: 0, FAIL: 0, SKIP: 0}
    for it in items:
        out[it["status"]] += 1
    return out


def _render(items) -> list:
    lines = []
    for it in items:
        lines.append(f"{it['status']:<5} {it['id']:<28} {it['detail']}")
        if it["status"] != PASS and it["hint"]:
            lines.append(f"{'':<34}-> {it['hint']}")
    sm = _summary(items)
    lines.append(f"Summary: {sm[PASS]} PASS, {sm[WARN]} WARN, {sm[FAIL]} FAIL, {sm[SKIP]} SKIP")
    return lines


def audit(s, args):
    f = gather(s, args)
    items = evaluate(f, args)
    sm = _summary(items)
    return _render(items), {"items": items, "summary": sm}, (1 if sm[FAIL] else 0)


# --- fix: plan ------------------------------------------------------------------------------------------------

def call(api, method, version, params=None) -> dict:
    return {"api": api, "method": method, "version": version, "params": params or {}}


def as_nas_api(c: dict) -> str:
    """The same call as a `nas api` command line."""
    parts = ["nas", "api", c["api"], c["method"], "--version", str(c["version"])]
    for k, v in (c.get("params") or {}).items():
        parts.append(f"{k}={v if isinstance(v, str) else json.dumps(v, separators=(',', ':'))}")
    if not is_read_method(c["method"]):
        parts.append("--allow-write")
    return " ".join(shlex.quote(p) for p in parts)


def _change(fix, target, before, after, calls, apply=None, verify=None, note="", refused=None) -> dict:
    return {"fix": fix, "target": target, "before": before, "after": after, "calls": calls,
            "apply": apply, "verify": verify, "note": note, "refused": refused}


def _send(s, calls):
    for c in calls:
        need(c["api"], s.call(c["api"], c["method"], c["params"], version=c["version"]))


def client_address(origin: str) -> tuple:
    """(address this machine uses to reach `origin`, the origin's address). Sends no packet."""
    u = urllib.parse.urlsplit(origin)
    host, port = u.hostname, u.port or 5001
    fam, _, _, _, sa = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)[0]
    sk = socket.socket(fam, socket.SOCK_DGRAM)
    try:
        sk.connect(sa)
        return sk.getsockname()[0], sa[0]
    finally:
        sk.close()


def current_account(s) -> str | None:
    """The DSM account of this session; asks DSM when it is not known (a pasted NAS_SID session)."""
    acct = getattr(s.backend, "account", None)
    if acct:
        return acct
    d, _ = part("SYNO.Core.Desktop.Initdata", s.call("SYNO.Core.Desktop.Initdata", "get", version=1))
    acct = ((d or {}).get("Session") or {}).get("user")
    if acct:
        try:
            s.backend.account = acct
        except AttributeError:
            pass
    return acct


def dsm_seen_address(f, account: str | None) -> str | None:
    """Source address DSM logged for the newest successful sign-in of `account` (the log is newest first)."""
    if not account:
        return None
    for x in f["log"][0] or []:
        descr = x.get("descr") or ""
        if "fail" in descr or not ("signed in" in descr or "logged in" in descr):
            continue
        if (_LOG_USER.search(descr) or [None, ""])[1] == account:
            return _ip_of((_LOG_FROM.search(descr) or [None, ""])[1])
    return None


def lockout_guard(s, f) -> tuple:
    """(address DSM sees for this machine, None) or (None, reason to refuse the firewall change)."""
    if s.backend_name == "local":
        return None, None
    origin = s.backend.select_origin() if hasattr(s.backend, "select_origin") else getattr(s.backend, "origin", None)
    host = urllib.parse.urlsplit(origin or "").hostname or ""
    proxies = {k: v for k, v in (get_proxies() or {}).items() if k in ("http", "https", "all")}
    if proxies and not proxy_bypass(host):
        return None, (f"proxies are configured ({', '.join(sorted(proxies))}); DSM may see the proxy's address. "
                      "Unset HTTP(S)_PROXY / the system proxy for this run (this CLI itself never uses them)")
    try:
        local_ip, origin_ip = client_address(origin)
    except (OSError, TypeError) as e:
        return None, f"cannot work out this machine's address: {e}"
    oa = ipaddress.ip_address(origin_ip)
    if oa.is_loopback:
        return None, (f"the origin {origin} is a loopback address (SSH tunnel or local proxy): DSM's view of this "
                      "machine is not known. Connect to the NAS's LAN address")
    if oa.is_global:
        return None, (f"this machine reaches DSM through a public address ({origin_ip}). Run the fix from the LAN "
                      "or a VPN (set origins to the LAN/VPN address)")
    account = current_account(s)
    seen = dsm_seen_address(f, account)
    if not seen:
        return None, f"no sign-in of {account or 'this session'} in DSM's connection log to tell which address DSM sees"
    try:
        sa = ipaddress.ip_address(seen)
    except ValueError:
        return None, f"DSM logged {seen!r} for this session, not an address"
    if sa.is_loopback:
        return None, (f"DSM sees this session as {seen} (Tailscale userspace mode, SSH tunnel or a local proxy), so "
                      "the firewall cannot be checked against it. Run the fix from the LAN")
    if sa.version == 6:
        return None, f"DSM sees this session over IPv6 ({seen}); this CLI writes IPv4 allow rules only"
    if sa.is_global:
        return None, f"DSM sees this session from a public address ({seen})"
    if seen != local_ip:
        return None, (f"DSM logged {seen} for the newest sign-in of {account}, but this machine uses {local_ip} "
                      "(NAT or a proxy in between, or that sign-in came from another device)")
    return seen, None


def configured_v4() -> tuple:
    """(IPv4 networks from allowed_networks without loopback/link-local, IPv6 entries, loopback entries)."""
    v4, v6, loop = [], [], []
    for n in config.get()["allowed_networks"]:
        try:
            net = ipaddress.ip_network(n, strict=False)
        except ValueError as e:
            raise NasError(f"allowed_networks: {e}")
        if net.version == 6:
            v6.append(str(net))
        elif net.is_loopback:
            loop.append(str(net))
        elif not net.is_link_local:
            v4.append(net)
    return v4, v6, loop


def firewall_allow_list(seen_ip: str | None) -> tuple:
    """(IPv4 networks to allow, IPv6 entries left out, the client /32 added or None)."""
    v4, v6, _ = configured_v4()
    added = None
    if seen_ip:
        a = ipaddress.ip_address(seen_ip)
        if not any(a.version == n.version and a in n for n in v4):
            added = ipaddress.ip_network(f"{seen_ip}/32")
            v4.append(added)
    return v4, v6, added


def _fw_rule(net) -> dict:
    return {"enable": True, "log": False, "name": "", "policy": "allow", "port_direction": "destination",
            "port_group": "all", "ports": "all", "protocol": "all",
            "source_ip": f"{net.network_address}/{net.netmask}", "source_ip_group": "netmask"}


def plan_firewall(s, f) -> dict | None:
    fw, _ = f["fw"]
    prof, e_prof = f["fw_profile"]
    if fw is None or prof is None:
        return _change("firewall", "firewall", "unreadable", "-", [], refused=f"cannot read the firewall profile ({e_prof})")
    name = fw.get("profile_name") or "default"
    seen, why = lockout_guard(s, f)
    if why:
        return _change("firewall", "firewall", "-", "-", [], refused=why)
    v4, v6, added = firewall_allow_list(seen)
    if not v4:
        return _change("firewall", "firewall", "-", "-", [], refused=(
            "nothing to allow: allowed_networks is empty and --backend local has no client address"))
    want = [_fw_rule(n) for n in v4]
    key = lambda r: (r.get("source_ip"), r.get("ports"), r.get("protocol"), r.get("policy"))  # noqa: E731
    adapters = _adapters(f)
    lan = [i.get("ifname") for i in (f["ifaces"][0] or []) if i.get("type") == "lan" and i.get("ifname") in adapters]
    targets = lan or ["global"]  # allow rules on the LAN interfaces; "global" applies to every interface
    new = {"name": name}
    dropped, adds = [], []
    for a in adapters + ([] if "global" in adapters else ["global"]):
        cur = prof.get(a) if isinstance(prof.get(a), dict) else {"policy": "allow", "rules": []}
        keep = []
        for r in cur.get("rules") or []:
            if r.get("policy") == "allow" and r.get("source_ip") == "all":
                dropped.append(f"{a}: allow any source to ports {r.get('ports')}")
            else:
                keep.append(r)
        rules = list(keep)
        if a in targets:
            have = {key(r) for r in keep}
            missing = [r for r in want if key(r) not in have]
            adds += [f"{r['source_ip']} on {a}" for r in missing]
            rules += missing
        new[a] = {"policy": "none" if a == "global" else "drop", "rules": rules}
    open_ad = [a for a in new if a not in ("name", "global") and (prof.get(a) or {}).get("policy") != "drop"]
    if fw.get("enable_firewall") and not adds and not open_ad and not dropped:
        return None
    before = ("off" if not fw.get("enable_firewall") else "on") + (
        f"; unmatched traffic allowed on {', '.join(open_ad)}" if open_ad else "") + (
        f"; missing allow rules: {', '.join(adds)}" if adds else "")
    after = (f"on (profile {name}): allow {', '.join(str(n) for n in v4)} on {', '.join(targets)}; drop everything "
             f"else on {', '.join(a for a in new if a not in ('name', 'global'))}")
    notes = []
    if added:
        notes.append(f"{added} added: the address DSM logged for this session")
    if not config.get()["allowed_networks"]:
        notes.append("allowed_networks is empty: only this computer will reach DSM and the file services; add your "
                     "LAN range (e.g. 192.168.0.0/24) to allowed_networks first if other devices need the NAS")
    if not lan:
        notes.append("no LAN interface found in the firewall profile: allow rules go to 'global' (every interface)")
    if any(n.overlaps(ipaddress.ip_network("100.64.0.0/10")) for n in v4) and _nas_public(f):
        notes.append("100.64.0.0/10 is also the range CGNAT ISPs use on the PPPoE side; the rules sit on the LAN "
                     "interfaces only, so PPPoE stays closed")
    if v6:
        notes.append(f"IPv6 entries not written as firewall rules ({', '.join(v6)}): IPv6 sources are dropped")
    if dropped:
        notes.append("removed rules: " + "; ".join(dropped))
    calls = [call("SYNO.Core.Security.Firewall.Profile", "set", 1, {"profile": new, "profile_applying": False}),
             call("SYNO.Core.Security.Firewall.Profile.Apply", "start", 1, {"name": name, "profile_applying": False}),
             call("SYNO.Core.Security.Firewall.Profile.Apply", "status", 1, {"task_id": "<task_id from start>"}),
             call("SYNO.Core.Security.Firewall.Profile.Apply", "stop", 1)]

    def apply(s_):
        need("SYNO.Core.Security.Firewall.Profile", s_.call("SYNO.Core.Security.Firewall.Profile", "set",
                                                              {"profile": new, "profile_applying": False}, version=1))
        st = need("SYNO.Core.Security.Firewall.Profile.Apply", s_.call(
            "SYNO.Core.Security.Firewall.Profile.Apply", "start", {"name": name, "profile_applying": False}, version=1))
        tid = (st or {}).get("task_id")
        ok = None
        for _ in range(60):
            time.sleep(1)
            d, _e = part("SYNO.Core.Security.Firewall.Profile.Apply", s_.call(
                "SYNO.Core.Security.Firewall.Profile.Apply", "status", {"task_id": tid}, version=1))
            if d and (d.get("finish") or "success" in d):
                ok = d.get("success", True)
                break
        s_.call("SYNO.Core.Security.Firewall.Profile.Apply", "stop", version=1)
        if ok is False:
            raise NasError("firewall profile apply reported failure")
        if ok is None:
            raise NasError("firewall profile apply did not finish within 60 s")

    def verify(s_):
        d = need("SYNO.Core.Security.Firewall", s_.call("SYNO.Core.Security.Firewall", "get", version=1))
        if not d.get("enable_firewall"):
            return False, "firewall still off"
        err = fresh_login_error(s_)
        if err:
            return False, f"firewall on, but a fresh login over the same origin failed: {err}\n{RESCUE}"
        return True, f"on (profile {d.get('profile_name')}); fresh login over the same origin works"

    return _change("firewall", "firewall", before, after, calls, apply, verify, note="; ".join(notes))


def fresh_login_error(s) -> str | None:
    """None when a brand-new login over the current origin works (password backend only)."""
    if s.backend_name != "password":
        return None
    b = PasswordBackend([s.backend.origin], s.backend.creds, s.backend.cfg, use_cache=False)
    try:
        b.login()
        r = b.call_many([{"api": "SYNO.Core.Security.Firewall", "method": "get", "version": 1}])[0]
        return None if r.get("ok") else describe_error("SYNO.Core.Security.Firewall", r)
    except NasError as e:
        return str(e)
    finally:
        try:
            b.logout()
        except NasError:
            pass


def plan(s, f, args) -> list:
    """Changes `incident fix` would make, in FIX_ORDER."""
    cfg = config.get()
    inc = cfg["incident"]
    out = []
    shares_filter = set(args.share or [])

    def want_share(share):
        return not shares_filter or share in shares_filter

    snap = f["snap"]
    sc = (f.get("scan") or (None, None))[0]
    scan_clean = bool(sc and sc.get("finished") and not (sc.get("root_hits") or sc.get("search_hits")))
    rotate_ok = scan_clean or getattr(args, "i_know_snapshots_may_rotate", False)
    rotate_why = (None if rotate_ok else
                  "snapshots that start being taken again apply their retention policy, which deletes older snapshots "
                  "you may need to recover encrypted files. Run with --ransom-scan (it must come back clean) or pass "
                  "--i-know-snapshots-may-rotate")
    # snapshot_worm: lock off where the model lacks immutable snapshots
    if snap and snap["worm_supported"] is False:
        for share in f["shares"]:
            st = snap["shares"][share]
            if want_share(share) and (st["worm"] or {}).get("worm_lock_enable"):
                c = call("SYNO.DisasterRecovery.Retention", "set_worm_lock", 1,
                         {"type": "Share", "name": share, "worm_lock_enable": False,
                          "worm_lock_day": st["worm"].get("worm_lock_day") or 7})

                def verify(s_, share=share):
                    d = need("SYNO.DisasterRecovery.Retention", s_.call(
                        "SYNO.DisasterRecovery.Retention", "get_worm_lock", {"name": share, "type": "Share"}, version=1))
                    return (not d.get("worm_lock_enable")), f"lock {'on' if d.get('worm_lock_enable') else 'off'}"
                out.append(_change("snapshot_worm", share, "immutable lock on (unsupported)", "lock off", [c],
                                   verify=verify, refused=rotate_why,
                                   note="the share's existing schedule starts taking snapshots again"))

    # snapshots: create a daily schedule where a share has none. Existing schedules (on or off) and an existing
    # retention policy are left alone.
    if snap:
        for share in f["shares"]:
            st = snap["shares"][share]
            if not want_share(share) or st["schedule"] is None or st["enabled"] or st["task_id"] not in (None, -1):
                continue
            h, m = inc["snapshot_hour"], inc["snapshot_minute"]
            sched = {"date": dt.date.today().strftime("%Y/%m/%d"), "date_type": 0, "week_name": "0,1,2,3,4,5,6",
                     "hour": h, "min": m, "repeat": 0, "repeat_hour": 0, "repeat_min": 0, "last_work_hour": h,
                     "monthly_week": []}
            calls = [call("SYNO.Core.Share.Snapshot", "set_schedule", 1,
                          {"name": share, "enable_snapshot_schedule": True, "schedule": sched, "task_id": -1})]
            after = f"daily {h:02d}:{m:02d}"
            note = "snapshots use free space on the volume"
            if rotate_why is None:
                ret, e = part("SYNO.DisasterRecovery.Retention", s.call(
                    "SYNO.DisasterRecovery.Retention", "get", {"name": share}, version=1))
                if ret is None:
                    out.append(_change("snapshots", share, "no schedule", "-", [],
                                       refused=f"cannot read the retention policy ({e})"))
                    continue
                if not ret.get("policyType"):
                    ret = {k: v for k, v in ret.items() if k not in ("name", "schedule")}
                    ret.update({"type": "Share", "policyType": 64, "retainDay": inc["snapshot_retain_days"]})
                    calls.append(call("SYNO.DisasterRecovery.Retention", "set", 1, dict({"name": share}, **ret)))
                    after += f", keep {inc['snapshot_retain_days']} days"
                else:
                    note += f"; the share's existing retention policy (type {ret.get('policyType')}) is kept"

            def verify(s_, share=share):
                d = need("SYNO.Core.Share.Snapshot", s_.call("SYNO.Core.Share.Snapshot", "get_schedule",
                                                           {"name": share}, version=1))
                nxt = (d.get("schedule") or {}).get("next_trigger_time")
                return bool(d.get("enable_snapshot_schedule")), f"schedule {'on' if d.get('enable_snapshot_schedule') else 'off'}, next {nxt}"
            out.append(_change("snapshots", share, "no snapshot schedule", after, calls, verify=verify,
                               refused=rotate_why, note=note))

    # packages named in SA-26:14 that are running
    pk, _ = f["pkgs"]
    for p in (pk or {}).get("packages", []):
        v = advisories.package_verdict(p.get("id"), p.get("version", ""))
        status = (p.get("additional") or {}).get("status")
        if v and v["status"] != "patched" and status == "running":
            pid = p["id"]

            def verify(s_, pid=pid):
                d = need("SYNO.Core.Package", s_.call("SYNO.Core.Package", "list", {"additional": ["status"]}, version=1))
                st = next(((x.get("additional") or {}).get("status") for x in d.get("packages", []) if x.get("id") == pid), None)
                return st != "running", f"status {st}"
            out.append(_change("packages", pid, f"{p.get('version')} running (SA-26:14 {v['status']})", "stopped",
                               [call("SYNO.Core.Package.Control", "stop", 1, {"id": pid})], verify=verify,
                               note=f"update to {v['fixed_in']} in Package Center" if v.get("fixed_in")
                               else "no fixed version: uninstall it"))

    # SMB minimum SMB2
    smb, _ = f["smb"]
    if smb is not None and smb.get("smb_min_protocol") == 0:
        mx = max(int(smb.get("smb_max_protocol") or 3), 1)

        def verify(s_):
            d = need("SYNO.Core.FileServ.SMB", s_.call("SYNO.Core.FileServ.SMB", "get"))
            return d.get("smb_min_protocol", 0) >= 1, f"min {d.get('smb_min_protocol')} max {d.get('smb_max_protocol')}"
        out.append(_change("smb_min_protocol", "SMB", "minimum SMB1", "minimum SMB2",
                           [call("SYNO.Core.FileServ.SMB", "set", 3, {"smb_min_protocol": 1, "smb_max_protocol": mx})],
                           verify=verify, note="SMB1-only clients lose access"))

    # QuickConnect off (+ its automatic router port forwarding)
    qc, _ = f["qc"]
    upnp, _ = f["qc_upnp"]
    calls = []
    if qc is not None and qc.get("enabled"):
        calls.append(call("SYNO.Core.QuickConnect", "set", 2, {"enabled": False}))
    if upnp is not None and upnp.get("enabled"):
        calls.append(call("SYNO.Core.QuickConnect.Upnp", "set", 1, {"enabled": False}))
    if calls:
        def verify(s_):
            d, _ = part("SYNO.Core.QuickConnect", s_.call("SYNO.Core.QuickConnect", "get"))
            u, _ = part("SYNO.Core.QuickConnect.Upnp", s_.call("SYNO.Core.QuickConnect.Upnp", "get", version=1))
            on = bool((d or {}).get("enabled")) or bool((u or {}).get("enabled"))
            return not on, f"QuickConnect {'on' if (d or {}).get('enabled') else 'off'}, auto port forwarding " \
                           f"{'on' if (u or {}).get('enabled') else 'off'}"
        before = ", ".join(x for x in ("QuickConnect on" if (qc or {}).get("enabled") else "",
                                       "automatic port forwarding on" if (upnp or {}).get("enabled") else "") if x)
        out.append(_change("quickconnect", "QuickConnect", before, "both off", calls, verify=verify,
                           note="apps that connect by QuickConnect ID need the LAN/VPN address instead"))

    # router port-forwarding rules DSM created: disable them
    pf, _ = f["pf"]
    rules = _pf_rules(pf) if pf is not None else None
    if rules and any(r.get("enable") for r in rules):
        new_rules = []
        for i, r in enumerate(rules):
            n = {"id": i}
            for k in ("enable", "rule_id", "ds_port", "router_port", "router_protocol", "serviceid", "service_name",
                      "force"):
                v = r.get(k)
                n[k] = (v.get("id") if isinstance(v, dict) else v) if k == "serviceid" else (v if v is not None else False)
            n["enable"] = False
            new_rules.append(n)

        def apply(s_):
            st = need("SYNO.Core.PortForwarding.Rules", s_.call("SYNO.Core.PortForwarding.Rules", "save",
                                                                {"rules": new_rules, "task_id_suffix": "PF"}, version=1))
            for _ in range(120):
                time.sleep(1)
                d, e = part("SYNO.Core.PortForwarding.Rules", s_.call(
                    "SYNO.Core.PortForwarding.Rules", "save_status", {"task_id": (st or {}).get("task_id")}, version=1))
                if d is None:
                    raise NasError(f"router rule save failed: {e}")
                if str(d.get("status")).lower() not in ("processing", "progress", "waiting"):
                    return
            raise NasError("router rule save did not finish within 120 s")

        def verify(s_):
            d, e = part("SYNO.Core.PortForwarding.Rules", s_.call("SYNO.Core.PortForwarding.Rules", "load", version=1))
            rs = _pf_rules(d) or []
            on = [r for r in rs if r.get("enable")]
            return not on, f"{len(on)} rule(s) still enabled" if on else "all rules disabled"
        out.append(_change("router_port_forwarding", "router", f"{sum(1 for r in rules if r.get('enable'))} rule(s) enabled",
                           "all disabled (kept in the list)",
                           [call("SYNO.Core.PortForwarding.Rules", "save", 1, {"rules": new_rules, "task_id_suffix": "PF"}),
                            call("SYNO.Core.PortForwarding.Rules", "save_status", 1, {"task_id": "<task_id from save>"})],
                           apply=apply, verify=verify,
                           note="the payload mirrors the DSM UI; check the router's own page afterwards"))

    # AutoBlock on + allow-list (loopback first: Tailscale userspace mode reaches DSM as 127.0.0.1)
    ab, _ = f["autoblock"]
    if ab is not None:
        # this machine as DSM logged it, the configured IPv4 networks, and loopback only when opted in
        allow = ["127.0.0.1"] if inc["autoblock_allow_loopback"] else []
        seen = dsm_seen_address(f, current_account(s)) if s.backend_name != "local" else None
        v4, _v6, _loop = configured_v4()
        if seen:
            try:
                a = ipaddress.ip_address(seen)
                if a.version == 4 and not a.is_loopback and not any(a in n for n in v4):
                    allow.append(seen)
            except ValueError:
                pass
        for net in v4:
            allow.append(str(net.network_address) if net.prefixlen == 32 else f"{net.network_address}/{net.netmask}")
        have = []
        for ip in allow:
            d, _e = part("SYNO.Core.Security.AutoBlock.Rules", s.call("SYNO.Core.Security.AutoBlock.Rules", "get",
                                                                     {"ip": ip}, version=1))
            if (d or {}).get("type") == "allow":
                have.append(ip)
        missing = [ip for ip in allow if ip not in have]
        calls = []
        if not ab.get("enable"):
            calls.append(call("SYNO.Core.Security.AutoBlock", "set", 1, {
                "enable": True, "attempts": inc["autoblock_attempts"], "within_mins": inc["autoblock_within_mins"],
                "enable_expire": bool(ab.get("expire_day")), "expire_day": int(ab.get("expire_day") or 0)}))
        if missing:
            calls.append(call("SYNO.Core.Security.AutoBlock.Rules", "create", 1,
                              {"type": "allow", "block_days": 0, "overwrite": True, "ip": missing}))
        if calls:
            def verify(s_, missing=missing):
                d = need("SYNO.Core.Security.AutoBlock", s_.call("SYNO.Core.Security.AutoBlock", "get"))
                bad = [ip for ip in missing if (part("SYNO.Core.Security.AutoBlock.Rules", s_.call(
                    "SYNO.Core.Security.AutoBlock.Rules", "get", {"ip": ip}, version=1))[0] or {}).get("type") != "allow"]
                ok = bool(d.get("enable")) and not bad
                return ok, (f"on, {d.get('attempts')} attempts / {d.get('within_mins')} min" if d.get("enable") else "off") + \
                    (f"; not on the allow list: {', '.join(bad)}" if bad else "")
            before = ("off" if not ab.get("enable") else "on") + (f"; allow list lacks {', '.join(missing)}" if missing else "")
            after = (f"on, {inc['autoblock_attempts']} attempts / {inc['autoblock_within_mins']} min"
                     if not ab.get("enable") else "on") + (f"; allow {', '.join(missing)}" if missing else "")
            out.append(_change("autoblock", "AutoBlock", before, after, calls, verify=verify,
                               note="allow-listed addresses are never blocked"))

    # built-in admin disabled. SYNO.Core.User set answers 105 from a password session (even after
    # PasswordConfirm); as root through synowebapi it works, so it runs in a one-off root task.
    us, _ = f["users"]
    admin = next((u for u in (us or {}).get("users", []) if u.get("name") == "admin"), None)
    if admin is not None and admin.get("expired") != "now":
        me = current_account(s) if s.backend_name != "local" else "root"
        members, e_adm = f["admins"]
        names = None
        if members is not None:
            rows = members.get("users") or members.get("members") or members.get("items") if isinstance(members, dict) else members
            names = {(r.get("name") if isinstance(r, dict) else r) for r in rows or []}
        enabled = {u.get("name") for u in (us or {}).get("users", []) if u.get("expired") != "now"}
        others = sorted((names or set()) & enabled - {"admin"})
        refused = None
        if not me:
            refused = "cannot tell which account this session uses (SYNO.Core.Desktop.Initdata)"
        elif me == "admin":
            refused = "this CLI is signed in as admin; sign in with another administrator first"
        elif names is None:
            refused = f"cannot list the administrators group ({e_adm}); disabling admin could leave no administrator"
        elif not others:
            refused = "no other enabled administrator exists; create one first"
        elif s.backend_name not in ("password", "local"):
            refused = "needs --backend password (a root task) or --backend local"
        user_set = call("SYNO.Core.User", "set", 1, {"name": "admin", "expired": "now"})
        script = ("/usr/syno/bin/synowebapi --exec api=SYNO.Core.User method=set version=1 "
                  "name='\"admin\"' expired='\"now\"'")

        def admin_disabled(s_):
            d, _e = part("SYNO.Core.User", s_.call("SYNO.Core.User", "get",
                                                   {"name": "admin", "additional": ["expired"]}, version=1))
            return ((d or {}).get("users") or [{}])[0].get("expired") == "now"

        def apply(s_):
            if s_.backend_name == "local":
                _send(s_, [user_set])
            else:
                from .selfmon import run_root_script
                run_root_script(s_, "nas-incident-fix", script, done=admin_disabled)

        def verify(s_):
            d = need("SYNO.Core.User", s_.call("SYNO.Core.User", "get", {"name": "admin", "additional": ["expired"]},
                                               version=1))
            u = (d.get("users") or [{}])[0]
            return u.get("expired") == "now", f"expired={u.get('expired')}"
        calls = ([user_set] if s.backend_name == "local" else [
            call("SYNO.Core.User.PasswordConfirm", "auth", 2, {"password": "<account password>"}),
            call("SYNO.Core.TaskScheduler.Root", "create", 4, {
                "name": "nas-incident-fix", "owner": "root", "real_owner": "root", "enable": False, "type": "script",
                "extra": {"script": script}, "SynoConfirmPWToken": "<token>"}),
            call("SYNO.Core.TaskScheduler", "run", 2, {"tasks": [{"id": "<task id>", "real_owner": "root"}]}),
            call("SYNO.Core.TaskScheduler", "delete", 2, {"tasks": [{"id": "<task id>", "real_owner": "root"}]})])
        out.append(_change("admin_account", "admin", f"enabled (expired={admin.get('expired')})", "disabled", calls,
                           apply=apply, verify=verify, refused=refused,
                           note="SYNO.Core.User set answers 105 from a password session; it runs as root in a "
                                "temporary Task Scheduler task (deleted afterwards)"))

    fwc = plan_firewall(s, f)
    if fwc:
        out.append(fwc)

    if args.rotate_password:
        out.append(plan_rotation(s))
    if args.upgrade:
        out.append(plan_upgrade(s, f, args))

    order = {k: i for i, k in enumerate(FIX_ORDER)}
    out.sort(key=lambda c: order[c["fix"]])
    only = {x.strip() for x in (args.only or "").split(",") if x.strip()}
    skip = {x.strip() for x in (args.skip or "").split(",") if x.strip()}
    unknown = (only | skip) - set(FIX_ORDER)
    if unknown:
        raise NasError(f"unknown fix name(s): {', '.join(sorted(unknown))} (known: {', '.join(FIX_ORDER)})")
    return [c for c in out if (not only or c["fix"] in only) and c["fix"] not in skip]


def _new_password() -> str:
    """24 characters with upper, lower, digit and a symbol DSM accepts in its default policy."""
    pool = string.ascii_letters + string.digits + "-_.!@#%+="
    while True:
        p = "".join(secrets.choice(pool) for _ in range(24))
        if (any(c.islower() for c in p) and any(c.isupper() for c in p) and any(c.isdigit() for c in p)
                and any(c in "-_.!@#%+=" for c in p)):
            return p


def plan_rotation(s) -> dict:
    if s.backend_name != "password":
        return _change("rotate_password", "password", "-", "-", [], refused="--rotate-password needs --backend password")
    creds = s.backend.creds
    where = creds.writable_store()
    if not where:
        return _change("rotate_password", "password", "-", "-", [], refused=(
            f"the password comes from '{creds.source()}', which this CLI cannot update; use a 1Password reference "
            "(credentials.op_password) or `nas login --save` (keychain) first"))
    account = current_account(s)
    if not account:
        return _change("rotate_password", "password", "-", "-", [], refused=(
            "cannot tell which account this session uses (SYNO.Core.Desktop.Initdata)"))
    calls = [call("SYNO.Core.NormalUser", "set", 2, {"password": "<new>", "old_password": "<current>"})]
    state = {}
    keep_old = ("the previous value stays in the 1Password item's history" if where == "op" else
                f"the previous value is kept in the keychain entry '{creds.cfg.get('store_service') or 'synology-nas-cli'}"
                "-previous'")

    def apply(s_):
        old = creds.password(account)
        new = _new_password()
        if where != "op":
            creds.store_write(account, old, service=(creds.cfg.get("store_service") or "synology-nas-cli") + "-previous")
        # 1. the store first, so the new password exists somewhere before DSM uses it
        try:
            creds.write_password(account, new)
        except BaseException:
            try:
                creds.write_password(account, old)
            except BaseException:
                print(f"nas: WARNING: the password store may now hold an unused password; DSM still uses the old one "
                      f"({keep_old})", file=sys.stderr)
            raise
        # 2. then DSM
        try:
            need("SYNO.Core.NormalUser", s_.call("SYNO.Core.NormalUser", "set", {"password": new, "old_password": old},
                                                 version=2))
        except NasError:  # DSM said no: it still has the old password, so the store gets it back
            try:
                creds.write_password(account, old)
            except BaseException as e2:
                raise NasError(f"DSM refused the change and putting the old password back into {where} failed ({e2}); "
                               f"DSM still uses the old password ({keep_old})")
            raise
        except BaseException:  # interrupted or no answer: DSM may or may not have the new one
            print(f"nas: WARNING: the DSM password change was interrupted. {where} holds the NEW password; if DSM "
                  f"still accepts the old one, {keep_old}.", file=sys.stderr)
            raise
        creds.remember(new)
        state["new"] = new

    def verify(s_):
        if creds.read_back(account) != state.get("new"):
            return False, f"the password read back from {where} does not match"
        err = fresh_login_error(s_)
        if err:
            return False, f"stored in {where}, but a fresh login with it failed: {err} ({keep_old})"
        return True, f"changed, stored in {where}, fresh login works"

    return _change("rotate_password", account, "current password", f"new random 24-character password in {where}",
                   calls, apply=apply, verify=verify,
                   note=f"written to {where} before DSM changes; {keep_old}; never printed")


def plan_upgrade(s, f, args) -> dict:
    it = next((x for x in evaluate(f, args) if x["id"] == "dsm_version"), None)
    if it and it["status"] == PASS:
        return _change("upgrade", "DSM", it["detail"], "-", [], refused="already patched; nothing to upgrade")
    if s.backend_name != "password":
        return _change("upgrade", "DSM", "-", "-", [], refused="--upgrade needs --backend password (uploads the .pat)")
    from . import upgrade as up

    def apply(s_):
        ns = types.SimpleNamespace(pat=None, dry_run=False, yes=True, force=False, wait_only=False,
                                   download_dir=config.path(config.get()["upgrade"]["cache_dir"]),
                                   lang=config.get()["upgrade"]["lang"], timeout=3600, ask_on_notes=True)
        lines, data = up.upgrade(s_, ns)
        for line in lines:
            print("  " + line, file=sys.stderr)
        if data.get("action") != "installed":
            raise NasError(f"upgrade did not install ({data.get('action')})")

    def verify(s_):
        d = need("SYNO.Core.System", s_.call("SYNO.Core.System", "info", version=1))
        v = advisories.dsm_verdict(d.get("firmware_ver", ""))
        return v["status"] == "patched", f"{d.get('firmware_ver')}: SA-26:13 {v['status']}"

    return _change("upgrade", "DSM", it["detail"] if it else "-", "newest official build for this model",
                   [call("SYNO.Core.Upgrade.Patch", "upload", 1, {"target": "active", "file": "<.pat>"}),
                    call("SYNO.Core.Upgrade.PreCheck", "start", 1, {"type": "patch"}),
                    call("SYNO.Core.Upgrade", "start", 1, {"force": True, "type": "patch"})],
                   apply=apply, verify=verify, note="the NAS reboots; DSM answers 499 until post-upgrade tasks finish")


# --- fix: run --------------------------------------------------------------------------------------------------

def _plan_lines(changes) -> list:
    lines = [f"Plan ({sum(1 for c in changes if not c['refused'])} change(s)):"] if changes else ["Nothing to change."]
    for n, c in enumerate(changes, 1):
        tag = "REFUSED " if c["refused"] else ""
        lines.append(f"{n:>2}. {tag}{c['fix']} [{c['target']}]: {c['before']} -> {c['after']}")
        if c["refused"]:
            lines.append(f"      why: {c['refused']}")
            continue
        if c["note"]:
            lines.append(f"      note: {c['note']}")
        for k in c["calls"]:
            lines.append(f"      {as_nas_api(k)}")
        ui = UI.get(c["fix"])
        if ui:
            lines.append(f"      UI: {ui[0]}")
            lines.append(f"          {ui[1]}")
    return lines


def _confirm(n: int) -> bool:
    if not can_prompt():
        return False
    sys.stderr.write(f"Apply {n} change(s) to the NAS? [y/N] ")
    sys.stderr.flush()
    return sys.stdin.readline().strip().lower() in ("y", "yes")


def fix(s, args):
    if args.ransom_scan:
        args.scan = True
    f = gather(s, args)
    before = evaluate(f, args)
    changes = plan(s, f, args)
    lines = _plan_lines(changes)
    runnable = [c for c in changes if not c["refused"]]
    data = {"before": before, "plan": [{k: v for k, v in c.items() if k not in ("apply", "verify")} for c in changes]}
    if args.dry_run or not runnable:
        if args.dry_run:
            lines.append("Dry run: nothing was sent.")
        return lines, data, (1 if any(c["refused"] for c in changes) and not args.dry_run else 0)
    if not args.yes and not _confirm(len(runnable)):
        lines.append("Not applied: confirm on a terminal or pass --yes (input is off: --no-input, NAS_NO_INPUT=1 or "
                     "no terminal)." if not can_prompt() else "Not applied (answer y, or pass --yes).")
        return lines, data, (InputRequired.exit_code if not can_prompt() else 1)

    results, failed = [], False
    for c in runnable:
        print(f"applying {c['fix']} [{c['target']}]...", file=sys.stderr)
        try:
            (c["apply"] or (lambda s_, c=c: _send(s_, c["calls"])))(s)
            ok, now = c["verify"](s) if c["verify"] else (True, "sent")
        except NasError as e:
            ok, now = False, f"error: {e}"
        failed |= not ok
        results.append({"fix": c["fix"], "target": c["target"], "ok": ok, "now": now})
        lines.append(f"{'OK  ' if ok else 'FAIL'} {c['fix']} [{c['target']}]: {now}")
        if not ok and c["fix"] == "firewall" and RESCUE not in now:
            lines.append(RESCUE)
    try:
        after = evaluate(gather(s, args), args)
    except NasError as e:  # e.g. this machine lost its path to DSM: keep what was applied and how to get back
        lines.append(f"Post-fix audit could not run: {e}")
        if RESCUE not in "\n".join(lines):
            lines.append(RESCUE)
        data.update(results=results, after=None, after_error=str(e))
        return lines, data, 1
    prev = {it["id"]: it["status"] for it in before}
    lines.append("Before -> after:")
    for it in after:
        b = prev.get(it["id"], "-")
        lines.append(f"  {b:<5} -> {it['status']:<5} {it['id']}" + ("" if b == it["status"] else "   (changed)"))
    sm = _summary(after)
    lines.append(f"After: {sm[PASS]} PASS, {sm[WARN]} WARN, {sm[FAIL]} FAIL, {sm[SKIP]} SKIP")
    data.update(results=results, after=after)
    return lines, data, (1 if failed or sm[FAIL] else 0)


def incident(s, args):
    if getattr(args, "action", None) == "fix":
        return fix(s, args)
    return audit(s, args)
