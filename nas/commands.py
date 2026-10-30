"""Commands. Each returns (lines, data): human text and a JSON-able dict.

All of them only read, except `api --allow-write`. `upgrade` lives in
upgrade.py; `pkg`, `volume`, `tailscale` in manage.py; `alert` in alert.py."""

from __future__ import annotations

import collections
import concurrent.futures
import datetime as dt
import ipaddress
import json
import re
import socket
import sys
import time
import urllib.parse

from . import advisories, config
from .backends import NasError, describe_error

_SECRET_KEY = re.compile(r"(passwd|password|username|serial|token|^sid$|secret|private_key)", re.I)


def scrub(obj):
    if isinstance(obj, dict):
        return {k: scrub(v) for k, v in obj.items() if not _SECRET_KEY.search(k)}
    if isinstance(obj, list):
        return [scrub(v) for v in obj]
    return obj


def need(api: str, r: dict):
    if not r.get("ok"):
        raise NasError(f"{api}: {describe_error(api, r)}")
    return r.get("data")


def part(api: str, r: dict):
    """(data, None) on success, (None, error text) otherwise."""
    if r.get("ok"):
        return r.get("data"), None
    return None, describe_error(api, r)


def _onoff(v) -> str:
    if v is None:
        return "?"
    return "ON" if v else "off"


def _uptime(s: str) -> str:
    try:
        h, m, sec = (int(x) for x in s.split(":"))
    except (ValueError, AttributeError):
        return str(s)
    return f"{h // 24}d {h % 24}h {m}m"


# --- status ---------------------------------------------------------------

def status(s, args):
    d = need("SYNO.Core.System", s.call("SYNO.Core.System", "info", version=1))
    fw = d.get("firmware_ver", "")
    verdict = advisories.dsm_verdict(fw)
    latest = config.get()["latest_dsm"] or None
    data = {
        "model": d.get("model"),
        "firmware_ver": fw,
        "firmware_date": d.get("firmware_date"),
        "uptime": _uptime(d.get("up_time", "")),
        "nas_time": d.get("time"),
        "sys_temp_c": d.get("sys_temp"),
        "ram_mb": d.get("ram_size"),
        "sa_26_13": verdict,
        "latest_for_model": latest,
    }
    lines = [
        f"Model        {data['model']}  RAM {data['ram_mb']} MB  temp {data['sys_temp_c']}°C",
        f"DSM          {fw}  (released {data['firmware_date']})",
        f"Uptime       {data['uptime']}  (NAS clock {data['nas_time']})",
        f"SA-26:13     {verdict['status']}" + (f" — {verdict['note']}" if verdict.get("note") else "")
        + (f" [fixed in {verdict['fixed_in']}]" if verdict.get("fixed_in") and verdict["status"] == "patched" else ""),
    ]
    if latest:
        lines.append(f"Latest DSM   {latest} (config latest_dsm)")
    return lines, data


# --- net ------------------------------------------------------------------

def _net_calls(s):
    return s.call_many([
        {"api": "SYNO.Core.Network.Interface", "method": "list"},
        {"api": "SYNO.Core.Network.PPPoE", "method": "list"},
        {"api": "SYNO.Core.Security.Firewall", "method": "get"},
        {"api": "SYNO.Core.Security.Firewall.Profile", "method": "list"},
        {"api": "SYNO.Core.Network", "method": "get"},
    ])


def net(s, args):
    r_if, r_ppp, r_fw, r_prof, r_net = _net_calls(s)
    ifaces, e_if = part("SYNO.Core.Network.Interface", r_if)
    ppp, e_ppp = part("SYNO.Core.Network.PPPoE", r_ppp)
    fw, e_fw = part("SYNO.Core.Security.Firewall", r_fw)
    prof, _ = part("SYNO.Core.Security.Firewall.Profile", r_prof)
    netg, e_net = part("SYNO.Core.Network", r_net)

    lines = ["Interfaces"]
    if_rows = []
    for i in ifaces or []:
        row = {k: i.get(k) for k in ("ifname", "type", "status", "ip", "mask", "use_dhcp")}
        if_rows.append(row)
        lines.append(f"  {row['ifname']:<7} {row['type']:<6} {row['status']:<13} "
                     f"{row['ip']}/{row['mask']}  {'dhcp' if row['use_dhcp'] else 'static'}")
    if e_if:
        lines.append(f"  (unavailable: {e_if})")

    lines.append("PPPoE")
    ppp_rows = []
    for p in ppp or []:
        row = {
            "ifname": p.get("ifname"), "on": p.get("real_ifname"), "status": p.get("status"),
            "ip": p.get("ip"), "ipv6": [a for a in p.get("ipv6", []) if not a.lower().startswith("fe80")],
            "default_gateway": bool(p.get("is_default_gateway")),
        }
        ppp_rows.append(row)
        lines.append(f"  {row['ifname']} on {row['on']}: {row['status']}, {row['ip']}, "
                     f"default gateway: {'yes' if row['default_gateway'] else 'no'}")
        for a in row["ipv6"]:
            lines.append(f"  IPv6 {a}")
    if not ppp_rows:
        lines.append(f"  (unavailable: {e_ppp})" if e_ppp else "  none")

    fw_data = None
    if fw is not None:
        fw_data = {"enabled": fw.get("enable_firewall"), "profile": fw.get("profile_name"),
                   "profiles": (prof or {}).get("profile_names")}
        lines.append(f"Firewall     {_onoff(fw_data['enabled'])}  (profile: {fw_data['profile']}; "
                     f"profiles: {', '.join(fw_data['profiles'] or [])})")
    else:
        lines.append(f"Firewall     (unavailable: {e_fw})")

    gw = scrub(netg) if isinstance(netg, dict) else None
    if gw:
        lines.append(f"Gateway      {gw.get('gateway') or '-'}  DNS {gw.get('dns_primary') or '-'} {gw.get('dns_secondary') or ''}".rstrip())
    elif e_net:
        lines.append(f"Gateway      (unavailable: {e_net})")

    data = {"interfaces": if_rows, "pppoe": ppp_rows, "firewall": fw_data, "network": gw}
    return lines, data


# --- services -------------------------------------------------------------

_SERVICE_CALLS = [
    ("ssh", "SYNO.Core.Terminal", "get"),
    ("ftp", "SYNO.Core.FileServ.FTP", "get"),
    ("sftp", "SYNO.Core.FileServ.FTP.SFTP", "get"),
    ("smb", "SYNO.Core.FileServ.SMB", "get"),
    ("afp", "SYNO.Core.FileServ.AFP", "get"),
    ("nfs", "SYNO.Core.FileServ.NFS", "get"),
    ("rsync", "SYNO.Backup.Service.NetworkBackup", "get"),
    ("quickconnect", "SYNO.Core.QuickConnect", "get"),
    ("autoblock", "SYNO.Core.Security.AutoBlock", "get"),
    ("dsm_web", "SYNO.Core.Web.DSM", "get"),
]


_SMB_PROTOCOLS = {0: "SMB1", 1: "SMB2", 2: "SMB2+LargeMTU", 3: "SMB3"}


def _smb(v) -> str:
    return _SMB_PROTOCOLS.get(v, str(v))


def services(s, args):
    res = s.call_many([{"api": api, "method": m} for _, api, m in _SERVICE_CALLS])
    got = {}
    errs = {}
    for (key, api, _), r in zip(_SERVICE_CALLS, res):
        d, e = part(api, r)
        if e:
            errs[key] = e
        else:
            got[key] = d or {}

    def g(key, field):
        return got.get(key, {}).get(field)

    summary = {
        "ssh": {"enabled": g("ssh", "enable_ssh"), "port": g("ssh", "ssh_port"), "telnet": g("ssh", "enable_telnet")},
        "ftp": {"enabled": g("ftp", "enable_ftp"), "ftps": g("ftp", "enable_ftps"), "port": g("ftp", "portnum")},
        "sftp": {"enabled": g("sftp", "enable"), "port": g("sftp", "portnum")},
        "smb": {"enabled": g("smb", "enable_samba"), "min_protocol": g("smb", "smb_min_protocol"),
                "max_protocol": g("smb", "smb_max_protocol")},
        "afp": {"enabled": g("afp", "enable_afp")},
        "nfs": {"enabled": g("nfs", "enable_nfs"), "v4": g("nfs", "enable_nfs_v4")},
        "rsync": {"enabled": g("rsync", "enable")},
        "quickconnect": {"enabled": g("quickconnect", "enabled"), "id": g("quickconnect", "server_alias"),
                         "region": g("quickconnect", "region")},
        "autoblock": {"enabled": g("autoblock", "enable"), "attempts": g("autoblock", "attempts"),
                      "within_mins": g("autoblock", "within_mins"), "expire_day": g("autoblock", "expire_day")},
        "dsm_web": {"http_port": g("dsm_web", "http_port"), "https_port": g("dsm_web", "https_port"),
                    "redirect_https": g("dsm_web", "enable_https_redirect")},
    }
    for key in summary:
        if key in errs:
            summary[key] = {"unavailable": errs[key]}

    def line(label, key, text):
        return f"{label:<13}{'(unavailable: ' + errs[key] + ')' if key in errs else text}"

    sm = summary
    lines = [
        line("SSH", "ssh", f"{_onoff(sm['ssh'].get('enabled'))} port {sm['ssh'].get('port')}  telnet {_onoff(sm['ssh'].get('telnet'))}"),
        line("FTP", "ftp", f"{_onoff(sm['ftp'].get('enabled'))} port {sm['ftp'].get('port')}  FTPS {_onoff(sm['ftp'].get('ftps'))}"),
        line("SFTP", "sftp", f"{_onoff(sm['sftp'].get('enabled'))} port {sm['sftp'].get('port')}"),
        line("SMB", "smb", f"{_onoff(sm['smb'].get('enabled'))}  protocols {_smb(sm['smb'].get('min_protocol'))}"
             f"..{_smb(sm['smb'].get('max_protocol'))}"),
        line("AFP", "afp", _onoff(sm["afp"].get("enabled"))),
        line("NFS", "nfs", f"{_onoff(sm['nfs'].get('enabled'))}  v4 {_onoff(sm['nfs'].get('v4'))}"),
        line("rsync", "rsync", _onoff(sm["rsync"].get("enabled"))),
        line("QuickConnect", "quickconnect", f"{_onoff(sm['quickconnect'].get('enabled'))}  id {sm['quickconnect'].get('id') or '-'}"),
        line("AutoBlock", "autoblock", f"{_onoff(sm['autoblock'].get('enabled'))}  {sm['autoblock'].get('attempts')} tries / "
             f"{sm['autoblock'].get('within_mins')} min, expire_day {sm['autoblock'].get('expire_day')}"),
        line("DSM web", "dsm_web", f"http {sm['dsm_web'].get('http_port')}  https {sm['dsm_web'].get('https_port')}  "
             f"redirect-to-https {_onoff(sm['dsm_web'].get('redirect_https'))}"),
    ]
    return lines, summary


# --- inventory ------------------------------------------------------------

def inventory(s, args):
    r_sh, r_pkg, r_ct, r_usr, r_task = s.call_many([
        {"api": "SYNO.FileStation.List", "method": "list_share", "version": 2},
        {"api": "SYNO.Core.Package", "method": "list", "params": {"additional": ["status"]}, "version": 1},
        {"api": "SYNO.Docker.Container", "method": "list", "params": {"limit": "-1", "offset": "0", "type": "all"}},
        {"api": "SYNO.Core.User", "method": "list",
         "params": {"type": "local", "offset": "0", "limit": "-1", "additional": ["expired", "2fa_status"]}, "version": 1},
        {"api": "SYNO.Core.TaskScheduler", "method": "list", "params": {"offset": "0", "limit": "-1"}},
    ])
    lines = []
    data = {}

    sh, e = part("SYNO.FileStation.List", r_sh)
    data["shares"] = [x.get("path") for x in (sh or {}).get("shares", [])]
    lines.append("Shares       " + (", ".join(data["shares"]) if not e else f"(unavailable: {e})"))

    pk, e = part("SYNO.Core.Package", r_pkg)
    data["packages"] = []
    lines.append("Packages" + (f"     (unavailable: {e})" if e else ""))
    for p in (pk or {}).get("packages", []):
        v = advisories.package_verdict(p.get("id"), p.get("version", ""))
        row = {"id": p.get("id"), "version": p.get("version"),
               "status": (p.get("additional") or {}).get("status"), "sa_26_14": v}
        data["packages"].append(row)
        flag = f"  SA-26:14 {v['status']}" + (f" (fixed {v['fixed_in']})" if v.get("fixed_in") else "") if v else ""
        lines.append(f"  {row['id']:<22} {row['version']:<16} {row['status']}{flag}")
    named = [r["id"] for r in data["packages"] if r["sa_26_14"]]
    lines.append("  SA-26:14 packages installed: " + (", ".join(named) if named else "none"))

    ct, e = part("SYNO.Docker.Container", r_ct)
    data["containers"] = [{"name": c.get("name"), "status": c.get("status"), "image": c.get("image")}
                          for c in (ct or {}).get("containers", [])]
    lines.append("Containers" + (f"   (unavailable: {e})" if e else ""))
    for c in data["containers"]:
        lines.append(f"  {c['name']:<40} {c['status']:<9} {c['image']}")

    us, e = part("SYNO.Core.User", r_usr)
    data["users"] = [{"name": u.get("name"), "expired": u.get("expired"), "2fa": u.get("2fa_status")}
                     for u in (us or {}).get("users", [])]
    lines.append("Users" + (f"        (unavailable: {e})" if e else ""))
    for u in data["users"]:
        state = "disabled" if u["expired"] == "now" else u["expired"]
        lines.append(f"  {u['name']:<20} {state:<9} 2FA {_onoff(u['2fa'])}")

    tk, e = part("SYNO.Core.TaskScheduler", r_task)
    data["tasks"] = [{"name": t.get("name"), "owner": t.get("owner"), "enabled": t.get("enable"),
                      "type": t.get("type"), "action": t.get("action"), "next": t.get("next_trigger_time")}
                     for t in (tk or {}).get("tasks", [])]
    lines.append("Scheduled tasks" + (f"  (unavailable: {e})" if e else ""))
    for t in data["tasks"]:
        lines.append(f"  {str(t['name']):<30} owner {t['owner']}  {'enabled' if t['enabled'] else 'disabled'}  "
                     f"{t['type']}  {t['action']}")
    if not e and not data["tasks"]:
        lines.append("  none")
    return lines, data


# --- ransom-scan ----------------------------------------------------------

RANSOM_PATTERN = "*.L0CK3D,*.LOCK3D,read-me3.txt"
_RANSOM_NAME = re.compile(r"(\.l[o0]ck3d$|^read-me3\.txt$)", re.I)


def ransom_scan(s, args):
    pattern = args.pattern or RANSOM_PATTERN
    sh = need("SYNO.FileStation.List", s.call("SYNO.FileStation.List", "list_share", version=2))
    shares = [x["path"] for x in sh.get("shares", [])]
    lines = [f"Shares: {', '.join(shares)}", f"Pattern: {pattern}"]

    # 1) Share roots: the ransom note lands in every encrypted folder.
    roots = s.call_many([{"api": "SYNO.FileStation.List", "method": "list", "version": 2,
                          "params": {"folder_path": p, "limit": "5000"}} for p in shares])
    root_hits = []
    for p, r in zip(shares, roots):
        d, e = part("SYNO.FileStation.List", r)
        if e:
            lines.append(f"  root {p}: unavailable ({e})")
            continue
        root_hits += [f["path"] for f in d.get("files", []) if _RANSOM_NAME.search(f.get("name", ""))]
    lines.append(f"Share roots: {len(root_hits)} hit(s)")

    # 2) Recursive File Station search across all shares. DSM 7.1 ignores
    # comma-separated globs (returns 0 hits), so run one task per pattern.
    patterns = [p.strip() for p in pattern.split(",") if p.strip()]
    tasks = {}
    for p in patterns:
        st = need("SYNO.FileStation.Search", s.call("SYNO.FileStation.Search", "start", version=2, params={
            "folder_path": shares, "recursive": "true", "pattern": p}))
        tasks[p] = st["taskid"]
    results = {p: {"finished": False, "total": 0, "hits": []} for p in patterns}
    deadline = time.time() + args.timeout
    try:
        while True:
            pending = [p for p in patterns if not results[p]["finished"]]
            res = s.call_many([{"api": "SYNO.FileStation.Search", "method": "list", "version": 2,
                                "params": {"taskid": json.dumps(tasks[p]), "offset": "0", "limit": "1000"}}
                               for p in pending])
            for p, r in zip(pending, res):
                d = need("SYNO.FileStation.Search", r)
                results[p] = {"finished": bool(d.get("finished")), "total": d.get("total", 0),
                              "hits": [f.get("path") for f in d.get("files", [])]}
            done = sum(r["finished"] for r in results.values())
            print(f"  searching… {done}/{len(patterns)} patterns done, "
                  f"{sum(r['total'] for r in results.values())} hit(s)", file=sys.stderr)
            if done == len(patterns) or time.time() > deadline:
                break
            time.sleep(3)
    finally:
        s.call_many([{"api": "SYNO.FileStation.Search", "method": m, "version": 2,
                      "params": {"taskid": json.dumps(t)}} for t in tasks.values() for m in ("stop", "clean")])

    finished = all(r["finished"] for r in results.values())
    total = sum(r["total"] for r in results.values())
    hits = sorted({h for r in results.values() for h in r["hits"]})
    for p in patterns:
        lines.append(f"  {p:<16} {results[p]['total']} hit(s){'' if results[p]['finished'] else ' (incomplete)'}")
    lines.append(f"Recursive search: {total} hit(s)" + ("" if finished else f" — TIMED OUT after {args.timeout}s, incomplete"))
    for h in (root_hits + hits)[:200]:
        lines.append(f"  {h}")
    if len(root_hits) + len(hits) > 200:
        lines.append("  … (truncated, use --json)")
    if args.pattern:
        lines.append(f"Verdict: custom pattern, {total} match(es){'' if finished else ' (incomplete)'}")
    else:
        lines.append("Verdict: " + ("NO ransom files found" if finished and not hits and not root_hits
                                     else "HITS FOUND (ransom notes and logs are the evidence for any recovery attempt)" if hits or root_hits
                                     else "incomplete"))
    data = {"shares": shares, "patterns": {p: {"total": r["total"], "finished": r["finished"]} for p, r in results.items()},
            "root_hits": root_hits, "search_total": total, "search_hits": hits, "finished": finished}
    return lines, data


# --- exposure -------------------------------------------------------------

PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 111: "rpcbind", 139: "NetBIOS", 443: "HTTPS",
    445: "SMB", 548: "AFP", 873: "rsync", 2049: "NFS", 3260: "iSCSI", 3261: "iSCSI", 3263: "iSCSI",
    3264: "iSCSI", 3265: "iSCSI", 3493: "UPS/NUT", 5000: "DSM http", 5001: "DSM https",
    5005: "WebDAV", 5006: "WebDAV https", 6690: "Drive", 8080: "alt http", 8443: "alt https",
}


def _probe(host: str, port: int, timeout: float) -> str:
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    sk = socket.socket(fam, socket.SOCK_STREAM)
    sk.settimeout(timeout)
    try:
        sk.connect((host, port))
        return "OPEN"
    except ConnectionRefusedError:
        return "closed"
    except socket.timeout:
        return "filtered"
    except OSError:
        return "unreach"
    finally:
        sk.close()


def public_addresses(s) -> tuple:
    """(public v4, public v6, where they came from). The NAS's own PPPoE link first, then config public_ip."""
    pub4, pub6, source = None, None, None
    try:
        ppp = s.call("SYNO.Core.Network.PPPoE", "list")
        for p in ppp.get("data") or [] if ppp.get("ok") else []:
            if p.get("status") == "connected" and p.get("ip"):
                pub4, source = p["ip"], "NAS PPPoE"
                pub6 = next((a.split("/")[0] for a in p.get("ipv6", []) if not a.lower().startswith("fe80")), None)
    except NasError as e:
        print(f"nas: could not ask the NAS for its PPPoE address ({e})", file=sys.stderr)
    if not pub4 and config.get()["public_ip"]:
        pub4, source = config.get()["public_ip"], "config public_ip"
    return pub4, pub6, source


def lan_target(s) -> str | None:
    cfg = config.get()
    if cfg["lan_ip"]:
        return cfg["lan_ip"]
    origin = getattr(s.backend, "origin", None) or (cfg["origins"][0] if cfg["origins"] else None)
    return urllib.parse.urlsplit(origin).hostname if origin else None


def probe_ports(targets: list, ports: dict, timeout: float) -> dict:
    """{(label, port): OPEN|closed|filtered|unreach} for every target x port, in parallel."""
    jobs = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        for label, host in targets:
            for port in ports:
                jobs[(label, port)] = ex.submit(_probe, host, port, timeout)
    return {k: f.result() for k, f in jobs.items()}


def exposure(s, args):
    pub4, pub6, source = public_addresses(s)
    lan = lan_target(s)
    targets = ([("LAN", lan)] if lan else []) + ([("public v4", pub4)] if pub4 else []) + \
        ([("public v6", pub6)] if pub6 else [])
    if not targets:
        raise NasError("nothing to probe: set lan_ip / public_ip in the config")
    res = probe_ports(targets, PORTS, args.probe_timeout)

    head = f"{'port':>5}  {'service':<13}" + "".join(f"{lbl:<11}" for lbl, _ in targets)
    lines = [
        "Probed FROM THIS MACHINE. When the public address belongs to your router, the public column goes out",
        "and back in through it (hairpin NAT): a hint, NOT proof of what the internet sees. Confirm from outside.",
        (f"public v4 = {pub4} ({source})" + (f", public v6 = {pub6}" if pub6 else "")) if pub4
        else "public address unknown (no PPPoE on the NAS and no public_ip in the config): LAN only",
        head,
    ]
    data = {"targets": dict(targets), "public_source": source, "ports": {}}
    for port, svc in PORTS.items():
        row = {lbl: res[(lbl, port)] for lbl, _ in targets}
        if all(v != "OPEN" for v in row.values()):
            continue
        data["ports"][port] = {"service": svc, **row}
        lines.append(f"{port:>5}  {svc:<13}" + "".join(f"{row[lbl]:<11}" for lbl, _ in targets))
    if not data["ports"]:
        lines.append("  (no open ports found)")
    return lines, data


# --- whoami -------------------------------------------------------------

def whoami(s, args):
    d = need("SYNO.Core.Desktop.Initdata", s.call("SYNO.Core.Desktop.Initdata", "get", version=1))
    sess = d.get("Session") or {}
    sysinfo, e = part("SYNO.Core.System", s.call("SYNO.Core.System", "info", version=1))
    where = s.describe()
    data = {
        "backend": where.get("backend"),
        "origin": where.get("origin") or ", ".join(where.get("origins") or []),
        "credentials": where.get("source"),
        "op_ref": where.get("op_ref"),
        "session": where.get("session"),
        "account": sess.get("user") or getattr(s.backend, "account", None),
        "is_admin": sess.get("is_admin"),
        "hostname": sess.get("hostname"),
        "dsm": (sysinfo or {}).get("firmware_ver") or
               f"DSM {sess.get('productversion')}-{sess.get('version')}",
        "model": (sysinfo or {}).get("model"),
    }
    lines = [
        f"Backend      {data['backend']}  via {data['origin']}",
        *([f"Credentials  {data['op_ref'] or where.get('store') or where.get('command') or data['credentials']}"
           f"  (source: {data['credentials']}; session: {data['session']})"] if data["credentials"] else []),
        f"Account      {data['account']}  admin: {'yes' if data['is_admin'] else 'no'}",
        f"NAS          {data['hostname']}  {data['model'] or ''}  {data['dsm']}",
    ]
    return lines, data


# --- health ---------------------------------------------------------------

def _tb(v) -> str:
    try:
        return f"{int(v) / 1e12:.2f} TB"
    except (TypeError, ValueError):
        return "?"


def health(s, args):
    r_st, r_ups, r_util, r_sys = s.call_many([
        {"api": "SYNO.Storage.CGI.Storage", "method": "load_info", "version": 1},
        {"api": "SYNO.Core.ExternalDevice.UPS", "method": "get"},
        {"api": "SYNO.Core.System.Utilization", "method": "get"},
        {"api": "SYNO.Core.System", "method": "info", "version": 1},
    ])
    lines, data = [], {}

    st, e = part("SYNO.Storage.CGI.Storage", r_st)
    data["disks"] = [{
        "id": d.get("id"), "name": d.get("longName") or d.get("name"), "model": (d.get("model") or "").strip(),
        "status": d.get("status"), "smart": d.get("smart_status"), "temp_c": d.get("temp"),
        "size": _tb(d.get("size_total")), "bad_sectors": d.get("unc"),
    } for d in (st or {}).get("disks", [])]
    data["pools"] = [{
        "id": p.get("id"), "status": p.get("status"), "raid": p.get("device_type") or p.get("raidType"),
        "used": _tb((p.get("size") or {}).get("used")), "total": _tb((p.get("size") or {}).get("total")),
    } for p in (st or {}).get("storagePools", [])]
    data["volumes"] = [{
        "id": v.get("id"), "status": v.get("status"), "fs": v.get("fs_type"), "atime": v.get("atime_opt"),
        "used": _tb((v.get("size") or {}).get("used")), "total": _tb((v.get("size") or {}).get("total")),
    } for v in (st or {}).get("volumes", [])]
    lines.append("Disks" + (f"        (unavailable: {e})" if e else ""))
    for d in data["disks"]:
        lines.append(f"  {d['id']:<4} {d['name']:<8} {d['model']:<20} {d['size']:<9} status {d['status']:<15} "
                     f"SMART {d['smart']:<7} {d['temp_c']}°C  bad sectors {d['bad_sectors']}")
    lines.append("Pools")
    for p in data["pools"]:
        lines.append(f"  {p['id']:<8} {p['status']:<10} {p['raid']:<26} {p['used']} / {p['total']}")
    lines.append("Volumes")
    for v in data["volumes"]:
        lines.append(f"  {v['id']:<9} {v['status']:<10} {v['fs']:<6} {v['used']} / {v['total']}  atime {v['atime']}")

    ups, e = part("SYNO.Core.ExternalDevice.UPS", r_ups)
    if ups is not None:
        data["ups"] = {"enabled": ups.get("enable"), "model": (ups.get("model") or "").strip(),
                       "status": ups.get("status"), "charge_pct": ups.get("charge"), "runtime_s": ups.get("runtime"),
                       "mode": ups.get("mode")}
        u = data["ups"]
        lines.append(f"UPS          {u['model'] or '-'} ({u['mode']})  {u['status']}  charge {u['charge_pct']}%  "
                     f"runtime {u['runtime_s']}s")
    else:
        data["ups"] = None
        lines.append(f"UPS          (unavailable: {e})")

    ut, e = part("SYNO.Core.System.Utilization", r_util)
    if ut is not None:
        c, m = ut.get("cpu") or {}, ut.get("memory") or {}
        # DSM reports load averages multiplied by 100 (13 means 0.13).
        load = [round((c.get(k) or 0) / 100, 2) for k in ("1min_load", "5min_load", "15min_load")]
        data["cpu"] = {"user_pct": c.get("user_load"), "system_pct": c.get("system_load"),
                       "other_pct": c.get("other_load"), "load": load}
        data["memory"] = {"total_mb": int(m.get("total_real", 0)) // 1024,
                          "avail_mb": int(m.get("avail_real", 0)) // 1024,
                          "used_pct": m.get("real_usage"), "swap_used_pct": m.get("swap_usage")}
        lines.append(f"CPU          user {c.get('user_load')}%  system {c.get('system_load')}%  "
                     f"load {load[0]} {load[1]} {load[2]}")
        mm = data["memory"]
        lines.append(f"Memory       {mm['used_pct']}% used, {mm['avail_mb']} / {mm['total_mb']} MB available, "
                     f"swap {mm['swap_used_pct']}%")
    else:
        lines.append(f"CPU/Memory   (unavailable: {e})")

    si, _ = part("SYNO.Core.System", r_sys)
    if si:
        data["system"] = {"temp_c": si.get("sys_temp"), "uptime": _uptime(si.get("up_time", "")),
                          "temp_warning": si.get("temperature_warning")}
        lines.append(f"System       {si.get('sys_temp')}°C  up {data['system']['uptime']}")
    return lines, data


# --- logs -----------------------------------------------------------------

_LOG_USER = re.compile(r"User \[([^\]]*)\]")
_LOG_FROM = re.compile(r"from \[([^\]]*)\]")
_LOG_VIA = re.compile(r"via \[([^\]]*)\]")
_IP_IN = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:]+)")


def _ip_of(src: str) -> str:
    m = _IP_IN.search(src or "")
    return m.group(1) if m else (src or "?")


def _is_internal(ip: str) -> bool:
    try:
        return not ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _since(text: str | None) -> str | None:
    if not text:
        return None
    t = text.strip().replace("-", "/")
    if not re.fullmatch(r"\d{4}/\d{2}/\d{2}( \d{2}:\d{2}(:\d{2})?)?", t):
        raise NasError("--since wants YYYY-MM-DD or 'YYYY-MM-DD HH:MM'")
    return t


def fetch_connection_log(s, since: str | None, limit: int) -> tuple[list[dict], int | None]:
    """Newest-first connection-log entries at/after `since` ('YYYY/MM/DD HH:MM'), at most `limit`."""
    items, start, total = [], 0, None
    while True:
        page = min(1000, limit - len(items))
        if page <= 0:
            break
        d = need("SYNO.Core.SyslogClient.Log", s.call("SYNO.Core.SyslogClient.Log", "list", version=1, params={
            "logtype": "connection", "start": str(start), "limit": str(page), "target": "LOCAL", "dir": "desc"}))
        got = d.get("items") or []
        total = d.get("total", total)
        stop = False
        for x in got:
            if since and (x.get("time") or "") < since:
                stop = True
                break
            items.append(x)
        start += len(got)
        if stop or not got or (total is not None and start >= total):
            break
    return items, total


def logs(s, args):
    since = _since(args.since)
    items, total = fetch_connection_log(s, since, args.limit)

    fails_user, fails_ip, ok_ext, kinds = (collections.Counter(), collections.Counter(), {}, collections.Counter())
    for x in items:
        descr = x.get("descr") or ""
        kinds[re.sub(r"\[[^\]]*\]", "[]", descr)] += 1
        user = (_LOG_USER.search(descr) or [None, "?"])[1]
        ip = _ip_of((_LOG_FROM.search(descr) or [None, ""])[1])
        if "fail" in descr:
            fails_user[user] += 1
            fails_ip[ip] += 1
        elif ("signed in" in descr or "logged in" in descr) and not _is_internal(ip):
            via = (_LOG_VIA.search(descr) or [None, "?"])[1]
            k = (user, ip, via)
            e = ok_ext.setdefault(k, {"user": user, "ip": ip, "via": via, "count": 0, "last": x.get("time")})
            e["count"] += 1

    times = sorted(x.get("time") or "" for x in items)
    data = {
        "fetched": len(items), "total_in_log": total, "since": since,
        "span": [times[0], times[-1]] if times else None,
        "failed": sum(fails_user.values()), "distinct_failing_ips": len(fails_ip),
        "failed_by_user": fails_user.most_common(args.top), "failed_by_ip": fails_ip.most_common(args.top),
        "external_success": sorted(ok_ext.values(), key=lambda e: e["last"] or "", reverse=True),
        "kinds": kinds.most_common(),
    }
    lines = [
        f"Connection log: {len(items)} entries fetched of {total} in the log"
        + (f", since {since}" if since else "") + (f", span {times[0]} → {times[-1]}" if times else ""),
        f"Failed sign-ins: {data['failed']} from {len(fails_ip)} distinct IPs",
        "  top users: " + ", ".join(f"{u} {n}" for u, n in data["failed_by_user"]),
        "  top IPs:   " + ", ".join(f"{i} {n}" for i, n in data["failed_by_ip"]),
        "Successful sign-ins from non-LAN IPs:" + ("" if ok_ext else " none"),
    ]
    for e in data["external_success"]:
        lines.append(f"  {e['last']}  {e['user']} from {e['ip']} via {e['via']}  ×{e['count']}")
    lines.append("Entry kinds:")
    for k, n in data["kinds"]:
        lines.append(f"  {n:>6}  {k[:110]}")
    return lines, data


# --- snapshots (shared by alert and incident) --------------------------------

def _snapshot_time(name: str):
    """'GMT+01-2026.10.30-03.30.01' (NAS local time) -> datetime, or None."""
    try:
        return dt.datetime.strptime(name.split("-", 1)[1], "%Y.%m.%d-%H.%M.%S")
    except (AttributeError, IndexError, ValueError):
        return None


def snapshot_state(s, shares: list) -> dict:
    """Scheduled-snapshot facts per share.

    {"retention_error": str|None, "worm_supported": bool|None,
     "shares": {share: {"schedule": dict|None, "error": str|None, "enabled": bool, "task_id": int|None,
                        "newest": datetime|None, "worm": dict|None, "worm_error": str|None}}}

    Immutable snapshots (WORM) need "worm" in SYNO.DisasterRecovery.Retention info's adv_features.
    On models without it, set_worm_lock still succeeds and scheduled snapshots then stop silently.
    """
    calls = [{"api": "SYNO.DisasterRecovery.Retention", "method": "info", "version": 1}]
    for share in shares:
        calls += [
            {"api": "SYNO.Core.Share.Snapshot", "method": "get_schedule", "version": 1, "params": {"name": share}},
            {"api": "SYNO.Core.Share.Snapshot", "method": "list", "version": 2,
             "params": {"name": share, "additional": ["schedule_snapshot"]}},
            {"api": "SYNO.DisasterRecovery.Retention", "method": "get_worm_lock", "version": 1,
             "params": {"name": share, "type": "Share"}},
        ]
    res = s.call_many(calls)
    ret_info, ret_err = part("SYNO.DisasterRecovery.Retention", res[0])
    out = {"retention_error": ret_err,
           "worm_supported": None if ret_info is None else "worm" in (ret_info.get("adv_features") or []),
           "shares": {}}
    for i, share in enumerate(shares):
        sched, e = part("SYNO.Core.Share.Snapshot", res[1 + 3 * i])
        snaps, _ = part("SYNO.Core.Share.Snapshot", res[2 + 3 * i])
        worm, we = part("SYNO.DisasterRecovery.Retention", res[3 + 3 * i])
        taken = [t for t in (_snapshot_time(x.get("time")) for x in (snaps or {}).get("snapshots") or []
                             if x.get("schedule_snapshot")) if t]
        out["shares"][share] = {
            "schedule": sched, "error": e, "enabled": bool((sched or {}).get("enable_snapshot_schedule")),
            "task_id": (sched or {}).get("task_id"), "newest": max(taken, default=None),
            "worm": worm, "worm_error": we,
        }
    return out


def list_shares(s) -> list:
    d = need("SYNO.FileStation.List", s.call("SYNO.FileStation.List", "list_share", version=2))
    return [x.get("name") or x.get("path", "").strip("/") for x in d.get("shares", [])]


# --- raw api --------------------------------------------------------------

_READ_VERBS = ("info", "query", "status", "check", "read", "show", "count")


def is_read_method(method: str) -> bool:
    m = method.lower()
    # get, getinfo, getjs, get_misc_config, list_share, load_info ...
    if m.startswith(("get", "list", "load")):
        return True
    # conf_get, smart_get, disk_list, system_info ...
    if m.endswith(("_get", "_list", "_info", "_status")):
        return True
    return any(m == v or m.startswith(v + "_") for v in _READ_VERBS)


def raw_api(s, args):
    if not is_read_method(args.method):
        if not args.allow_write:
            raise NasError(f"method {args.method!r} looks like a write; pass --allow-write to send it")
    params = {}
    for kv in args.params:
        if "=" not in kv:
            raise NasError(f"parameter {kv!r} is not k=v")
        k, v = kv.split("=", 1)
        params[k] = v
    r = s.call(args.api_name, args.method, params=params, version=args.version)
    if not r.get("ok"):
        raise NasError(f"{args.api_name}.{args.method}: {describe_error(args.api_name, r)}")
    data = r.get("data")
    return [json.dumps(data, ensure_ascii=False, indent=2), f"(v{r.get('version')})"], data
