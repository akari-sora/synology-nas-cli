"""Offline checks of `nas incident contain`: the root script runs for real against a fake /proc tree with an
injected signal function; candidate detection, SIGSTOP + thread-state verification (T / D / running),
--pid, --save-exe, --stop-sync, --release, and the JSON against schemas/incident-contain.schema.json."""
import json
import os
import sys
import types

import _env

from nas import contain, incident
from jsonschema_min import validate

R = os.path.join(_env.TMP, "croot")
SIGLOG = os.path.join(_env.TMP, "signals.log")
_env.use_config({"session": {"cache_file": os.path.join(_env.TMP, "c", "session.json")},
                 "incident": {"ioc_process_names": ["evilcrypt"]}})
SCHEMA = json.load(open(os.path.join(_env.ROOT, "schemas", "incident-contain.schema.json")))


def put(path, content, mode=0o644):
    p = R + path
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(content)
    os.chmod(p, mode)


def proc(pid, exe, comm, tasks, cpu_ticks=0, start=0, fds=(), cgroup="", cmd=None):
    d = f"/proc/{pid}"
    os.makedirs(R + d + "/fd", exist_ok=True)
    if exe:
        os.symlink(exe, R + d + "/exe")
    put(d + "/comm", comm + "\n")
    put(d + "/cmdline", (cmd or exe or "").replace(" ", "\0"))
    f = ["0"] * 52
    f[0], f[11], f[19] = tasks[0][1], str(cpu_ticks), str(start)
    put(d + "/stat", f"{pid} ({comm}) " + " ".join(f))
    put(d + "/status", f"Name:\t{comm}\nThreads:\t{len(tasks)}\n")
    put(d + "/cgroup", cgroup)
    for tid, state in tasks:
        g = list(f)
        g[0] = state
        put(f"{d}/task/{tid}/stat", f"{tid} ({comm}) " + " ".join(g))
    for i, target in enumerate(fds, 3):
        os.symlink(target, R + f"{d}/fd/{i}")


def set_states(pid, states):
    for tid, st in states.items():
        p = R + f"/proc/{pid}/task/{tid}/stat"
        s = open(p).read()
        i = s.rfind(")")
        open(p, "w").write(s[:i + 2] + st + s[i + 3:])


put("/proc/uptime", "10000.00 9000.00\n")
os.makedirs(R + "/root", exist_ok=True)
put("/bin/libgld", "ELF-libgld")
put("/tmp/.x/enc", "ELF-enc")
proc(101, "/usr/syno/sbin/synoscgi", "synoscgi", [(101, "S")], cpu_ticks=1000)
proc(202, "/bin/libgld", "libgld", [(202, "T"), (203, "T")])
proc(303, "/tmp/.x/enc (deleted)", "enc", [(303, "T"), (304, "D")],
     fds=["/volume1/docs/report.pdf.L0CK3D", "/volume1/docs/read-me3.txt", "/dev/null"])
proc(404, "/opt/miner/bin/m", "m", [(404, "R")], cpu_ticks=900000)       # 9000 s of CPU in 10000 s: 90 %
proc(505, "/opt/app/x", "x", [(505, "R")], cpu_ticks=900000, cgroup="0::/docker/abc")  # container: not by CPU
proc(606, "/usr/bin/python3", "python3", [(606, "S")])
proc(707, None, "kworker/0:1", [(707, "S")])                              # kernel thread
proc(808, "/usr/bin/evilcrypt", "evilcrypt", [(808, "T")])                # incident.ioc_process_names


def args(**kw):
    a = dict(release=False, pid=None, stop_sync=False, save_exe=None, cpu_threshold=50.0, yes=False)
    a.update(kw)
    return types.SimpleNamespace(**a)


class Sess:
    backend_name = "password"

    def __init__(self):
        self.pkgs = {"CloudSync": "running", "HyperBackup": "stop", "ContainerManager": "running", "PHP7.4": "running"}
        self.sent = []

    def call(self, api, method, params=None, version=None, timeout=None):
        self.sent.append((api, method, (params or {}).get("id")))
        if (api, method) == ("SYNO.Core.Package", "list"):
            return {"ok": True, "data": {"packages": [{"id": k, "additional": {"status": v}} for k, v in self.pkgs.items()]}}
        if api == "SYNO.Core.Package.Control":
            self.pkgs[params["id"]] = "running" if method == "start" else "stop"
            return {"ok": True, "data": None}
        return {"ok": False, "error": {"code": 102}}


EXTRA = {"signal_log": SIGLOG, "clk_tck": 100}


def run(**kw):
    s = kw.pop("session", None) or Sess()
    return contain.contain(s, args(**kw), root=R, extra=EXTRA), s


def signals():
    return open(SIGLOG).read().split("\n")[:-1] if os.path.exists(SIGLOG) else []


def check(data):
    errs = validate(json.loads(json.dumps(data)), SCHEMA, SCHEMA)
    assert not errs, errs[:5]


# scan without --yes and without a terminal: candidates listed, nothing signalled, exit 3
(lines, data, rc), _ = run()
cands = {c["pid"]: c for c in data["candidates"]}
assert set(cands) == {202, 303, 404, 808}, sorted(cands)
assert "known name" in cands[202]["reasons"] and "runs from /bin/" in cands[202]["reasons"]
assert cands[303]["open_ransom_files"] == 2 and "runs from /tmp/.x/" in cands[303]["reasons"]
assert any("90% CPU outside Synology paths" == r for r in cands[404]["reasons"]) and cands[404]["cpu"] == 90.0
assert cands[808]["reasons"] == ["known name"]
assert rc == 3 and lines[-1] == "Not applied: add --yes (or NAS_YES=1)." and signals() == [] and data["mode"] == "scan"
check(data)

# --yes: SIGSTOP each candidate (never SIGKILL), verify every thread
(lines, data, rc), _ = run(yes=True, pid=[606])
sig = signals()
assert sorted(sig) == ["202 SIGSTOP", "303 SIGSTOP", "404 SIGSTOP", "606 SIGSTOP", "808 SIGSTOP"], sig
assert not any("KILL" in x for x in sig)
fr = {f["pid"]: f for f in data["frozen"]}
assert fr[202] == {"pid": 202, "threads": 2, "stopped": 2, "io_wait": 0, "other": 0, "gone": False, "ok": True}
assert fr[303]["stopped"] == 1 and fr[303]["io_wait"] == 1 and not fr[303]["ok"]
assert fr[404]["other"] == 1 and not fr[404]["ok"] and rc == 1
text = "\n".join(lines)
assert "waiting on I/O (state D): re-check with nas incident contain --pid 303 --yes" in text
assert contain.RESCUE_URL in text and "nas incident --deep" in text and "/proc/PID/exe" in text
assert sorted(json.load(open(R + "/root/.nas-incident-contain.json"))["pids"]) == [202, 303, 404, 606, 808]
assert oct(os.stat(R + "/root/.nas-incident-contain.json").st_mode & 0o777) == "0o600"
check(data)

# --save-exe: copies into a root-only folder, sha256 recorded; --stop-sync stops the running sync packages
os.remove(SIGLOG)
(lines, data, rc), sess = run(yes=True, save_exe="/root/evidence", stop_sync=True)
assert oct(os.stat(R + "/root/evidence").st_mode & 0o777) == "0o700"
saved = {x["pid"]: x for x in data["saved"]}
assert open(R + saved[202]["path"]).read() == "ELF-libgld" and len(saved[202]["sha256"]) == 64
assert {x["id"] for x in data["paused"]} == {"CloudSync", "ContainerManager"} and all(x["stopped"] for x in data["paused"])
assert sess.pkgs["CloudSync"] == "stop" and sess.pkgs["HyperBackup"] == "stop" and sess.pkgs["PHP7.4"] == "running"
check(data)

# --release: SIGCONT to the recorded PIDs, threads running again, packages started again, state removed
os.remove(SIGLOG)
for pid, st in ((202, {202: "S", 203: "S"}), (303, {303: "S", 304: "S"}), (404, {404: "R"}), (808, {808: "S"})):
    set_states(pid, st)
(lines, data, rc), _ = run(release=True, session=sess)
assert sorted(signals()) == ["202 SIGCONT", "303 SIGCONT", "404 SIGCONT", "808 SIGCONT"], signals()
assert all(r["ok"] for r in data["released"]) and rc == 0, data
assert {x["id"] for x in data["resumed"]} == {"CloudSync", "ContainerManager"} and sess.pkgs["CloudSync"] == "running"
assert not os.path.exists(R + "/root/.nas-incident-contain.json")
check(data)

# nothing suspicious: exit 0, no signals
os.remove(SIGLOG)
for pid in (202, 303, 404, 808):
    import shutil
    shutil.rmtree(R + f"/proc/{pid}")
(lines, data, rc), _ = run(yes=True)
assert rc == 0 and data["candidates"] == [] and signals() == [] and "Nothing to freeze" in lines[-1]

# the CLI parses the subcommand and its flags
from nas import cli
a = cli.parse_args(["incident", "contain", "--pid", "12", "--pid", "13", "--stop-sync", "--save-exe", "/root/x", "--yes"])
assert a.action == "contain" and a.pid == [12, 13] and a.stop_sync and a.save_exe == "/root/x" and a.yes
print(f"contain checks ok (python {sys.version.split()[0]})")
