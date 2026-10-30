"""`nas incident contain`: first response while a NAS is being encrypted (C3RB3R / .L0CK3D).

The encryptor's session keys live in its memory; tools such as c3rb3r-rescue recover them from a memory dump
while the process exists and the NAS has not rebooted. This command finds candidate encryptor processes and
freezes them with SIGSTOP (the process and every thread stay in memory), optionally pauses the sync/backup
packages that would push encrypted files over good copies, and lists the next steps.

One root script (CONTAIN, Python 3.8) runs through the same mechanism as `incident --deep`: a temporary
Task Scheduler root task with --backend password, or directly with --backend local. Modes: scan (report),
freeze (SIGSTOP + verify every thread's state), release (SIGCONT to the PIDs the last freeze recorded).
"""

from __future__ import annotations

import json
import os
import sys
import time

from . import config
from .commands import need, part
from .errors import InputRequired, NasError, can_prompt
from .ioc import clean, run_root_python

RESCUE_URL = "https://github.com/soimy/c3rb3r-rescue"
SYNC_PACKAGES = ["CloudSync", "HyperBackup", "ContainerManager", "Docker"]

CONTAIN = r'''
import hashlib, json, os, re, signal, sys, time
OUT, TOKEN, CFG = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
R = CFG.get("root", "")
MODE = CFG["mode"]
res = {"marker": TOKEN, "version": 1, "mode": MODE, "time": time.strftime("%Y-%m-%d %H:%M:%S"), "errors": [],
       "candidates": [], "frozen": [], "released": [], "saved": []}
ALLOWED = re.compile(r"^(/usr/syno/|/usr/bin/|/usr/sbin/|/bin/|/sbin/|/usr/lib/|/usr/lib64/|/lib/|/lib64/|"
                     r"/usr/libexec/|/usr/local/|/usr/share/|/var/packages/|/volume\d+/@appstore/|"
                     r"/volume\d+/@docker/|/volume\d+/@apphome/)")
BAD_DIR = re.compile(r"^(/tmp/|/var/tmp/|/dev/shm/|/run/shm/|/volume\d+/@tmp/)")
RANSOM = re.compile(r"(\.l[o0]ck3d$|(^|/)read-me3\.txt$)", re.I)
NAMES = set(["libgld", "qnetd"] + list(CFG.get("names", [])))
CLK = CFG.get("clk_tck") or (os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100)
STATE = R + CFG["state_file"]


def P(p):
    return R + p


def err(where, e):
    res["errors"].append("%s: %s" % (where, str(e)[:200]))


def read(p, n=4096):
    try:
        with open(p, "rb") as f:
            return f.read(n).decode("utf-8", "replace")
    except OSError:
        return ""


def signal_pid(pid, signum):
    if CFG.get("signal_log"):  # tests: record instead of signalling
        with open(CFG["signal_log"], "a") as f:
            f.write("%d %s\n" % (pid, signal.Signals(signum).name))
        return
    os.kill(pid, signum)


def task_states(pid):
    out = {}
    tdir = P("/proc/%d/task" % pid)
    try:
        tids = os.listdir(tdir)
    except OSError:
        tids = [str(pid)]
        tdir = P("/proc")
    for t in tids:
        s = read(tdir + "/" + t + "/stat")
        i = s.rfind(")")
        if i < 0:
            continue
        st = s[i + 2:i + 3]
        out[t] = st
    return out


try:
    uptime = float(read(P("/proc/uptime")).split()[0])
except (ValueError, IndexError):
    uptime = 0.0
explicit = set(int(p) for p in CFG.get("pids", []))
me = set() if R else {os.getpid(), os.getppid()}


def scan():
    for pid in os.listdir(P("/proc")) if os.path.isdir(P("/proc")) else []:
        if not pid.isdigit() or int(pid) in me:
            continue
        d = P("/proc/" + pid)
        try:
            exe = os.readlink(d + "/exe")
        except OSError:
            exe = ""
        if not exe and int(pid) not in explicit:
            continue  # kernel threads
        comm = read(d + "/comm").strip()
        cmd = read(d + "/cmdline", 400).replace("\0", " ").strip()
        st = read(d + "/stat")
        i = st.rfind(")")
        f = st[i + 2:].split() if i >= 0 else []
        try:
            ticks = int(f[11]) + int(f[12])
            start = int(f[19]) / float(CLK)
            cpu = round(100.0 * ticks / float(CLK) / max(1.0, uptime - start), 1)
        except (IndexError, ValueError):
            cpu = 0.0
        threads = 0
        for line in read(d + "/status", 8192).splitlines():
            if line.startswith("Threads:"):
                threads = int(line.split()[1])
        evidence, n = [], 0
        try:
            for fd in os.listdir(d + "/fd"):
                try:
                    t = os.readlink(d + "/fd/" + fd)
                except OSError:
                    continue
                if RANSOM.search(t.replace(" (deleted)", "")):
                    n += 1
                    if len(evidence) < 10:
                        evidence.append(t)
        except OSError:
            pass
        container = "docker" in read(d + "/cgroup") or "containerd" in read(d + "/cgroup")
        base = exe.replace(" (deleted)", "").rsplit("/", 1)[-1]
        reasons = []
        if base in NAMES or comm in NAMES or base.lower().startswith("xdy5"):
            reasons.append("known name")
        if BAD_DIR.match(exe) or exe.startswith("/bin/libgld"):
            reasons.append("runs from " + exe.rsplit("/", 1)[0] + "/")
        if n:
            reasons.append("holds %d ransom file(s) open" % n)
        if not container and cpu >= CFG.get("cpu_threshold", 50) and exe and not ALLOWED.match(exe):
            reasons.append("%.0f%% CPU outside Synology paths" % cpu)
        if int(pid) in explicit:
            reasons.append("--pid")
        if reasons:
            res["candidates"].append({"pid": int(pid), "exe": exe, "comm": comm, "cmdline": cmd[:400], "cpu": cpu,
                                      "threads": threads, "open_ransom_files": n, "evidence": evidence,
                                      "container": container, "reasons": reasons})


def verify(pid, want_stopped):
    states = {}
    for _ in range(10):
        states = task_states(pid)
        stopped = sum(1 for s in states.values() if s in "Tt")
        if not states or (want_stopped and stopped == len(states)) or (not want_stopped and stopped == 0):
            break
        if not R:
            time.sleep(0.2)
    stopped = sum(1 for s in states.values() if s in "Tt")
    io = sum(1 for s in states.values() if s == "D")
    return {"pid": pid, "threads": len(states), "stopped": stopped, "io_wait": io,
            "other": len(states) - stopped - io, "gone": not states,
            "ok": bool(states) and (stopped == len(states) if want_stopped else stopped == 0)}


if MODE in ("scan", "freeze"):
    scan()
if MODE == "freeze":
    for c in res["candidates"]:
        pid = c["pid"]
        try:
            signal_pid(pid, signal.SIGSTOP)
        except ProcessLookupError:
            res["frozen"].append({"pid": pid, "gone": True, "ok": False})
            continue
        except OSError as e:
            err("SIGSTOP %d" % pid, e)
            continue
        res["frozen"].append(verify(pid, True))
    if CFG.get("save_exe"):
        dst_dir = P(CFG["save_exe"])
        try:
            if os.path.islink(dst_dir):
                raise OSError("is a symlink")
            os.makedirs(dst_dir, mode=0o700, exist_ok=True)
            os.chmod(dst_dir, 0o700)
            for c in res["candidates"]:
                src = P("/proc/%d/exe" % c["pid"]) if not R else R + c["exe"].replace(" (deleted)", "")
                name = "%d-%s" % (c["pid"], (c["exe"].replace(" (deleted)", "").rsplit("/", 1)[-1] or "exe"))
                dst = os.path.join(dst_dir, name)
                h = hashlib.sha256()
                fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with open(src, "rb") as fsrc:
                    while True:
                        b = fsrc.read(1 << 20)
                        if not b:
                            break
                        h.update(b)
                        os.write(fd, b)
                os.close(fd)
                res["saved"].append({"pid": c["pid"], "path": dst[len(R):], "sha256": h.hexdigest(),
                                     "size": os.path.getsize(dst)})
        except OSError as e:
            err("--save-exe " + CFG["save_exe"], e)
    frozen = [f["pid"] for f in res["frozen"] if not f.get("gone")]
    if frozen:
        tmp = STATE + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        os.write(fd, json.dumps({"time": res["time"], "pids": frozen}).encode())
        os.close(fd)
        os.replace(tmp, STATE)
        res["state_file"] = CFG["state_file"]
if MODE == "release":
    try:
        with open(STATE) as f:
            pids = json.load(f).get("pids", [])
    except (OSError, ValueError):
        pids = []
    pids = sorted(set(pids) | explicit)
    for pid in pids:
        try:
            signal_pid(pid, signal.SIGCONT)
        except ProcessLookupError:
            res["released"].append({"pid": pid, "gone": True, "ok": True})
            continue
        except OSError as e:
            err("SIGCONT %d" % pid, e)
            continue
        res["released"].append(verify(pid, False))
    if os.path.exists(STATE):
        os.remove(STATE)

data = (json.dumps(res) + "\n").encode()
if OUT == "-":
    sys.stdout.buffer.write(data)
else:
    fd = os.open(OUT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    os.write(fd, data)
    os.close(fd)
'''


def script_config(mode: str, args, root: str = "", extra: dict | None = None) -> dict:
    inc = config.get()["incident"]
    cfg = {"root": root, "mode": mode, "names": list(inc["ioc_process_names"]), "pids": list(args.pid or []),
           "cpu_threshold": args.cpu_threshold, "state_file": inc["contain_state_file"],
           "save_exe": args.save_exe if mode == "freeze" else None}
    cfg.update(extra or {})
    return cfg


def _local_state_path() -> str:
    return os.path.join(os.path.dirname(config.path(config.get()["session"]["cache_file"])), "contain-packages.json")


def _sync_packages(s) -> list:
    d, _ = part("SYNO.Core.Package", s.call("SYNO.Core.Package", "list", {"additional": ["status"]}, version=1))
    return [p for p in (d or {}).get("packages", []) if p.get("id") in SYNC_PACKAGES]


def pause_sync(s) -> list:
    """Stop running sync/backup/container packages; returns what was stopped (recorded for --release)."""
    out = []
    for p in _sync_packages(s):
        if (p.get("additional") or {}).get("status") != "running":
            continue
        r = s.call("SYNO.Core.Package.Control", "stop", {"id": p["id"]}, version=1, timeout=300)
        out.append({"id": p["id"], "stopped": bool(r.get("ok")), "error": None if r.get("ok") else str(r.get("error"))})
    if out:
        path = _local_state_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"time": time.strftime("%Y-%m-%d %H:%M:%S"), "packages": [x["id"] for x in out if x["stopped"]]}, f)
        os.replace(path + ".tmp", path)
    return out


def resume_sync(s) -> list:
    path = _local_state_path()
    try:
        with open(path) as f:
            ids = json.load(f).get("packages", [])
    except (OSError, ValueError):
        return []
    out = []
    for pid in ids:
        r = s.call("SYNO.Core.Package.Control", "start", {"id": pid}, version=1, timeout=300)
        out.append({"id": pid, "started": bool(r.get("ok")), "error": None if r.get("ok") else str(r.get("error"))})
    if all(x["started"] for x in out):
        os.remove(path)
    return out


def next_steps(frozen: list, saved: list) -> list:
    pids = [str(f["pid"]) for f in frozen if f.get("ok") or f.get("stopped")]
    steps = [
        "Keep the NAS powered on and running: a reboot or power-off ends the frozen processes and the keys in their "
        "memory.",
        f"Capture the memory of each frozen process (PIDs {', '.join(pids) or '-'}) with c3rb3r-rescue, following its "
        f"guide: {RESCUE_URL}",
        "Copy each executable to external storage as root: cp /proc/PID/exe /path/on/usb/PID.bin"
        + (" (copies already saved: " + ", ".join(clean(x["path"], 80) for x in saved) + ")" if saved else
           " (or rerun with --save-exe DIR)"),
        "Preserve logs: copy /var/log (synoplugin.log*, synoscgi.log*, auth.log*, messages*) as root, and "
        "nas --json logs --limit 20000 > logs.json",
        "Scope: nas incident --deep",
        "After the memory capture: nas incident contain --release (SIGCONT; packages paused with --stop-sync start "
        "again), or keep the processes frozen while the NAS is isolated.",
    ]
    return steps


def contain(s, args, root: str = "", extra: dict | None = None):
    if args.release:
        d = run_root_python(s, CONTAIN, script_config("release", args, root, extra), "nas-incident-contain",
                            "contain script", root=root, timeout=300)
        resumed = resume_sync(s) if s.backend_name in ("password", "local") else []
        lines = ["Released (SIGCONT):"] + [
            f"  pid {r['pid']}: " + ("gone" if r.get("gone") else "running" if r["ok"] else
                                     f"{r['stopped']} of {r['threads']} thread(s) still stopped") for r in d["released"]]
        if not d["released"]:
            lines.append("  no PIDs recorded by a previous freeze")
        lines += [f"Package {x['id']}: " + ("started" if x["started"] else f"start failed ({x['error']})") for x in resumed]
        data = {"mode": "release", "released": d["released"], "resumed": resumed, "errors": d["errors"]}
        return lines, data, (0 if all(r["ok"] for r in d["released"]) and all(x["started"] for x in resumed) else 1)

    scan = run_root_python(s, CONTAIN, script_config("scan", args, root, extra), "nas-incident-contain",
                           "contain script", root=root, timeout=300)
    cands = scan["candidates"]
    lines = [f"Candidate encryptor processes: {len(cands)}"]
    for c in cands:
        lines.append(f"  pid {c['pid']} {clean(c['exe'], 80)} cpu {c['cpu']}% threads {c['threads']}: "
                     + "; ".join(c["reasons"]))
        lines.append(f"      cmdline: {clean(c['cmdline'], 160)}")
        for e in c["evidence"][:3]:
            lines.append(f"      open: {clean(e, 120)}")
    data = {"mode": "scan", "candidates": cands, "frozen": [], "paused": [], "saved": [], "errors": scan["errors"]}
    if not cands and not args.stop_sync:
        lines.append("Nothing to freeze. Scope: nas incident --deep")
        data["next_steps"] = ["nas incident --deep", "nas incident --scan"]
        return lines, data, 0
    if not args.yes:
        if not can_prompt():
            lines.append("Not applied: add --yes (or NAS_YES=1).")
            return lines, data, InputRequired.exit_code
        sys.stderr.write(f"Freeze {len(cands)} process(es) with SIGSTOP" + (" and pause sync packages" if args.stop_sync
                                                                            else "") + "? [y/N] ")
        sys.stderr.flush()
        if sys.stdin.readline().strip().lower() not in ("y", "yes"):
            lines.append("Not applied.")
            return lines, data, 1

    d = scan
    if cands:
        d = run_root_python(s, CONTAIN, script_config("freeze", dict_args(args, pids=[c["pid"] for c in cands]), root,
                                                      extra), "nas-incident-contain", "contain script", root=root,
                            timeout=300)
    paused = pause_sync(s) if args.stop_sync else []
    lines.append("Frozen (SIGSTOP; no process is killed):")
    for f in d.get("frozen", []):
        if f.get("gone"):
            lines.append(f"  pid {f['pid']}: exited before it could be frozen")
            continue
        state = f"{f['stopped']}/{f['threads']} thread(s) stopped"
        if f["io_wait"]:
            state += f", {f['io_wait']} waiting on I/O (state D): re-check with nas incident contain --pid {f['pid']} --yes"
        if f["other"]:
            state += f", {f['other']} still running"
        lines.append(f"  pid {f['pid']}: {state}")
    for x in paused:
        lines.append(f"Paused package {x['id']}: " + ("stopped" if x["stopped"] else f"stop failed ({x['error']})"))
    for x in d.get("saved", []):
        lines.append(f"Saved executable: {clean(x['path'], 100)} sha256 {x['sha256']}")
    steps = next_steps(d.get("frozen", []), d.get("saved", []))
    lines.append("Next steps:")
    lines += [f"  {i}. {t}" for i, t in enumerate(steps, 1)]
    data.update(mode="freeze", frozen=d.get("frozen", []), saved=d.get("saved", []), paused=paused,
                errors=scan["errors"] + d.get("errors", []), state_file=d.get("state_file"), next_steps=steps)
    ok = all(f.get("ok") for f in data["frozen"]) and all(x["stopped"] for x in paused)
    return lines, data, (0 if ok else 1)


def dict_args(args, **over):
    """A copy of argparse args with some fields replaced."""
    import types
    d = dict(vars(args))
    d.update(over)
    d["pid"] = sorted(set((args.pid or []) + over.get("pids", [])))
    return types.SimpleNamespace(**d)
