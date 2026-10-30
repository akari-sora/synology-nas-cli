"""`nas incident rescue`: recover C3RB3R / .L0CK3D file keys from the encryptor's memory, end to end.

Orchestrates the community toolkit c3rb3r-rescue (fetched at run time at a pinned commit; none of its code
is part of this repository) with this CLI's own pieces:

  contain   freeze the encryptor processes (nas incident contain --yes) unless --no-contain
  toolkit   clone c3rb3r-rescue at incident.rescue_commit and verify the SHA (or use --rescue-dir)
  capture   on the NAS as root: the toolkit's capture_process_memory.py `inspect` + `capture` for every
            frozen PID into a new case folder under --capture-dir (a different volume or USB disk than
            the encrypted data; --force to use the same volume); exe hash compared with the reviewed one
  pull      download the capture to the local workdir (skip with --keep-on-nas)
  venv      a venv in the workdir with the toolkit's pinned requirements; its self-tests
  keys      recover_process_key.py on every capture -> candidates (files mode 400, never printed)
  sample    --sample NAS_FILE: copy, inspect_footer.py, decrypt_copy.py with each candidate
  decrypt   --decrypt-from NAS_FOLDER --decrypt-to DIR: copies decrypted with the verified candidate

Every step records its result in <workdir>/state.json; running the same command again continues where
it stopped. Nothing is written back to the NAS's data volumes except the capture folder chosen with
--capture-dir.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import types

from . import config
from .errors import InputRequired, NasError, can_prompt
from .ioc import clean, run_root_python

STEPS = ["contain", "toolkit", "capture", "pull", "venv", "keys", "sample", "decrypt"]
SCRIPTS = "skills/dsm-ransomware-rescue/scripts"
PROFILE = "skills/dsm-ransomware-rescue/assets/libgld-802ac85d.json"
SUFFIX = re.compile(r"\.(l[o0]ck3d)$", re.I)

CAPTURE = r'''
import base64, glob, json, os, subprocess, sys, time
OUT, TOKEN, CFG = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
R = CFG.get("root", "")
res = {"marker": TOKEN, "version": 1, "errors": [], "captures": [], "case_dir": None, "same_volume": None}


def dev(p):
    try:
        return os.stat(p).st_dev
    except OSError:
        return None


cap = CFG["capture_dir"]
affected = {}
for p in CFG.get("affected_paths") or []:
    d = dev(R + p)
    if d is not None:
        affected[d] = p
if not affected:
    for v in sorted(glob.glob(R + "/volume[0-9]*")):
        d = dev(v)
        if d is not None:
            affected.setdefault(d, v[len(R):])
try:
    os.makedirs(cap, mode=0o700, exist_ok=True)
except OSError as e:
    res["errors"].append("capture dir: %s" % e)
cdev = dev(cap)
if cdev in affected:
    res["same_volume"] = affected[cdev]
if res["errors"] or (res["same_volume"] and not CFG.get("force")):
    pass
else:
    case = os.path.join(cap, CFG["case"])
    os.mkdir(case, 0o700)
    res["case_dir"] = case
    tool = os.path.join(case, ".capture_process_memory.py")
    fd = os.open(tool, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    os.write(fd, base64.b64decode(CFG["tool_b64"]))
    os.close(fd)
    for pid in CFG["pids"]:
        item = {"pid": pid}
        ins = subprocess.run([sys.executable, "-I", "-B", tool, "inspect", "--pid", str(pid)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
        if ins.returncode != 0:
            item.update(error="inspect: " + ins.stderr.decode("utf-8", "replace")[-400:])
            res["captures"].append(item)
            continue
        info = json.loads(ins.stdout.decode("utf-8", "replace"))
        item["inspect"] = {"state": info.get("state"), "start_ticks": info.get("start_ticks"),
                           "exe_sha256": info.get("exe_sha256"), "readable_bytes": info.get("readable_bytes"),
                           "threads": {k: v.get("state") for k, v in (info.get("threads") or {}).items()},
                           "excluded_unaddressable": len(info.get("excluded_unaddressable") or [])}
        out = os.path.join(case, "pid-%d" % pid)
        c = subprocess.run([sys.executable, "-I", "-B", tool, "capture", "--pid", str(pid),
                            "--expected-start-ticks", str(info["start_ticks"]),
                            "--expected-exe-sha256", info["exe_sha256"],
                            "--expected-output-device", str(os.stat(case).st_dev), "--output", out],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=CFG.get("timeout", 14400))
        item.update(exit=c.returncode, output=out, stderr=c.stderr.decode("utf-8", "replace")[-400:])
        lines = [l for l in c.stdout.decode("utf-8", "replace").splitlines() if l.strip().startswith("{")]
        if lines:
            try:
                item["summary"] = json.loads(lines[-1])
            except ValueError:
                pass
        res["captures"].append(item)
    os.remove(tool)
data = (json.dumps(res) + "\n").encode()
if OUT == "-":
    sys.stdout.buffer.write(data)
else:
    fd = os.open(OUT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    os.write(fd, data)
    os.close(fd)
'''


# --- workdir state -------------------------------------------------------------------------------------------

class Workdir:
    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        os.makedirs(self.path, mode=0o700, exist_ok=True)
        os.chmod(self.path, 0o700)
        self.file = os.path.join(self.path, "state.json")
        try:
            with open(self.file) as f:
                self.state = json.load(f)
        except (OSError, ValueError):
            self.state = {"version": 1, "created": dt.datetime.now().isoformat(timespec="seconds"), "steps": {}}

    def sub(self, *parts) -> str:
        p = os.path.join(self.path, *parts)
        os.makedirs(p, mode=0o700, exist_ok=True)
        return p

    def done(self, step: str) -> dict | None:
        s = self.state["steps"].get(step)
        return s if s and s.get("status") == "done" else None

    def record(self, step: str, status: str, **data) -> dict:
        entry = dict(data, status=status, time=dt.datetime.now().isoformat(timespec="seconds"))
        self.state["steps"][step] = entry
        tmp = self.file + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self.state, f, indent=2)
        os.replace(tmp, self.file)
        return entry


def default_workdir() -> str:
    return os.path.expanduser("~/.local/share/synology-nas-cli/rescue/" + dt.datetime.now().strftime("%Y%m%d-%H%M%S"))


def _run(argv, cwd=None, env=None, timeout=3600) -> subprocess.CompletedProcess:
    return subprocess.run(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                          timeout=timeout)


def _last_json(text: str):
    for line in reversed((text or "").strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                continue
    try:
        return json.loads(text)
    except ValueError:
        return None


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# --- NAS files (File Station for --backend password, the filesystem for --backend local) ---------------------

class NasFiles:
    def __init__(self, s, root: str = ""):
        self.s, self.root = s, root

    def real(self, fs_path: str) -> str:
        from .selfmon import share_real_path
        return share_real_path(self.s, fs_path)

    def local(self) -> bool:
        return self.s.backend_name == "local" or bool(self.root)

    def walk(self, real_dir: str, fs_dir: str):
        """(relative path, File Station path, real path) of every file below a folder."""
        if self.local():
            for dirpath, _dirs, files in os.walk(real_dir):
                for n in sorted(files):
                    rp = os.path.join(dirpath, n)
                    rel = os.path.relpath(rp, real_dir)
                    yield rel, fs_dir.rstrip("/") + "/" + rel.replace(os.sep, "/"), rp
            return
        stack = [(fs_dir.rstrip("/"), "")]
        while stack:
            folder, prefix = stack.pop()
            offset = 0
            while True:
                r = self.s.call("SYNO.FileStation.List", "list", {"folder_path": folder, "offset": offset,
                                                                 "limit": 1000}, version=2)
                if not r.get("ok"):
                    raise NasError(f"list {folder}: {r.get('error')}")
                files = (r.get("data") or {}).get("files") or []
                for f in files:
                    rel = (prefix + "/" + f["name"]).lstrip("/")
                    if f.get("isdir"):
                        stack.append((f["path"], rel))
                    else:
                        yield rel, f["path"], None
                offset += len(files)
                if not files or offset >= (r.get("data") or {}).get("total", 0):
                    break

    def fetch(self, fs_path: str, real_path: str | None, dest: str) -> int:
        os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
        if self.local():
            src = real_path or self.real(fs_path)
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            n = 0
            with open(src, "rb") as fsrc, os.fdopen(fd, "wb") as out:
                for b in iter(lambda: fsrc.read(1 << 20), b""):
                    out.write(b)
                    n += len(b)
            return n
        return self.s.backend.download_to(fs_path, dest)


# --- steps ---------------------------------------------------------------------------------------------------

def step_contain(s, args, wd, root, extra):
    from .contain import contain
    ns = types.SimpleNamespace(release=False, pid=list(args.pid or []), stop_sync=args.stop_sync, save_exe=None,
                               cpu_threshold=args.cpu_threshold, yes=True)
    lines, data, rc = contain(s, ns, root=root, extra=extra)
    frozen = [f["pid"] for f in data.get("frozen", []) if f.get("ok")]
    evidence = sorted({e for c in data.get("candidates", []) for e in c.get("evidence", [])})
    return wd.record("contain", "done" if frozen else "failed", frozen=frozen, frozen_detail=data.get("frozen", []),
                     evidence=evidence, paused=data.get("paused", []),
                     message="" if frozen else "no frozen process (no candidates, or threads not in state T)")


def step_toolkit(args, wd):
    inc = config.get()["incident"]
    want = inc["rescue_commit"]
    if args.rescue_dir:
        path = os.path.abspath(args.rescue_dir)
        r = _run(["git", "-C", path, "rev-parse", "HEAD"], timeout=60) if os.path.isdir(os.path.join(path, ".git")) else None
        head = r.stdout.strip() if r is not None and r.returncode == 0 else None
    else:
        path = os.path.join(wd.path, "c3rb3r-rescue")
        if not os.path.isdir(os.path.join(path, ".git")):
            r = _run(["git", "clone", "--quiet", "--no-checkout", inc["rescue_repo"], path], timeout=600)
            if r.returncode != 0:
                return wd.record("toolkit", "failed", message="git clone: " + clean(r.stderr, 300))
        r = _run(["git", "-C", path, "checkout", "--quiet", "--detach", want], timeout=120)
        if r.returncode != 0:
            return wd.record("toolkit", "failed", message=f"git checkout {want}: " + clean(r.stderr, 300))
        r = _run(["git", "-C", path, "rev-parse", "HEAD"], timeout=60)
        head = r.stdout.strip()
        if head != want:
            return wd.record("toolkit", "failed", path=path, commit=head, pinned=want,
                             message=f"checked-out commit {head} is not the pinned {want}")
    missing = [p for p in (f"{SCRIPTS}/capture_process_memory.py", f"{SCRIPTS}/recover_process_key.py",
                           f"{SCRIPTS}/inspect_footer.py", f"{SCRIPTS}/decrypt_copy.py", PROFILE, "requirements.txt")
               if not os.path.isfile(os.path.join(path, p))]
    if missing:
        return wd.record("toolkit", "failed", path=path, commit=head, message="missing in the toolkit: " + ", ".join(missing))
    with open(os.path.join(path, PROFILE)) as f:
        prof = json.load(f)
    return wd.record("toolkit", "done", path=path, commit=head, pinned=want, commit_matches=head == want,
                     reviewed_sha256={"packed": prof.get("packed_sha256"), "unpacked": prof.get("unpacked_sha256")})


def step_capture(s, args, wd, root):
    tk = wd.done("toolkit")
    pids = sorted(set((wd.done("contain") or {}).get("frozen", []) + list(args.pid or [])))
    if not pids:
        return wd.record("capture", "failed", message="no PID to capture: run with containment or --pid N")
    files = NasFiles(s, root)
    real = files.real(args.capture_dir)
    with open(os.path.join(tk["path"], SCRIPTS, "capture_process_memory.py"), "rb") as f:
        tool = f.read()
    case = "case-" + dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    cfg = {"root": root, "capture_dir": real, "case": case, "pids": pids, "force": bool(args.force),
           "affected_paths": (wd.done("contain") or {}).get("evidence", []), "tool_b64": base64.b64encode(tool).decode(),
           "timeout": 14400}
    d = run_root_python(s, CAPTURE, cfg, "nas-incident-rescue", "capture script", root=root, timeout=14400)
    if d.get("same_volume") and not args.force:
        return wd.record("capture", "failed", same_volume=d["same_volume"], message=(
            f"{args.capture_dir} is on the same volume as the encrypted data ({d['same_volume']}): use a USB disk or "
            "another volume (override: --force)"))
    reviewed = set(filter(None, tk["reviewed_sha256"].values()))
    caps = []
    for c in d.get("captures", []):
        sha = (c.get("inspect") or {}).get("exe_sha256")
        c["reviewed_sha256_match"] = bool(sha and sha in reviewed)
        c["fs_output"] = args.capture_dir.rstrip("/") + "/" + case + "/pid-%d" % c["pid"]
        caps.append(c)
    ok = [c for c in caps if c.get("exit") in (0, 2)]
    return wd.record("capture", "done" if ok else "failed", case=case, case_dir=d.get("case_dir"),
                     fs_case_dir=args.capture_dir.rstrip("/") + "/" + case, captures=caps,
                     same_volume=d.get("same_volume"), errors=d.get("errors", []),
                     message="" if ok else "no capture finished (see captures[].error / stderr)")


def step_pull(s, args, wd, root):
    cap = wd.done("capture")
    files = NasFiles(s, root)
    pulled = []
    for c in cap["captures"]:
        if c.get("exit") not in (0, 2):
            continue
        dest_dir = wd.sub("captures", "pid-%d" % c["pid"])
        real = c["output"] if files.local() else None
        n = 0
        for rel, fsp, rp in files.walk(real or "", c["fs_output"]):
            dest = os.path.join(dest_dir, rel)
            if os.path.exists(dest):
                continue  # resume
            n += files.fetch(fsp, rp, dest)
        manifest = os.path.join(dest_dir, "capture.json")
        bad = []
        if os.path.exists(manifest):
            with open(manifest) as f:
                m = json.load(f)
            for r in m.get("regions", []):
                p = os.path.join(dest_dir, r.get("file", ""))
                if r.get("sha256") and (not os.path.exists(p) or _sha256(p) != r["sha256"]):
                    bad.append(r.get("file"))
        pulled.append({"pid": c["pid"], "dir": dest_dir, "bytes": n, "manifest": os.path.exists(manifest),
                       "checksum_mismatch": bad})
    ok = pulled and all(p["manifest"] and not p["checksum_mismatch"] for p in pulled)
    return wd.record("pull", "done" if ok else "failed", pulled=pulled,
                     message="" if ok else "missing capture.json or region checksum mismatch")


def _python(args) -> str | None:
    need = tuple(int(x) for x in config.get()["incident"]["rescue_min_python"].split("."))
    for cand in ([args.python] if args.python else []) + ["python3.13", "python3.12", "python3.11", "python3"]:
        exe = shutil.which(cand) if not os.path.isabs(cand) else cand
        if not exe:
            continue
        r = _run([exe, "-c", "import sys; print('%d.%d' % sys.version_info[:2])"], timeout=30)
        if r.returncode == 0 and tuple(int(x) for x in r.stdout.strip().split(".")) >= need:
            return exe
    return None


def step_venv(args, wd):
    tk = wd.done("toolkit")
    py = _python(args)
    if not py:
        return wd.record("venv", "failed", message=f"no Python >= {config.get()['incident']['rescue_min_python']} "
                                                    "found (--python PATH)")
    venv = os.path.join(wd.path, "venv")
    vpy = os.path.join(venv, "Scripts" if os.name == "nt" else "bin", "python")
    if not os.path.exists(vpy):
        r = _run([py, "-m", "venv", venv], timeout=600)
        if r.returncode != 0:
            return wd.record("venv", "failed", message="venv: " + clean(r.stderr, 300))
    r = _run([vpy, "-m", "pip", "install", "--disable-pip-version-check", "--quiet", "-r",
              os.path.join(tk["path"], "requirements.txt")], timeout=1800)
    if r.returncode != 0:
        return wd.record("venv", "failed", python=vpy, message="pip install -r requirements.txt: " + clean(r.stderr[-400:], 400))
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([os.path.join(tk["path"], SCRIPTS), os.path.join(tk["path"], "scripts")]))
    t = _run([vpy, "-m", "unittest", "discover", "-s", "tests"], cwd=tk["path"], env=env, timeout=1800)
    vb = os.path.join(tk["path"], SCRIPTS, "verify_backup.py")
    st = _run([vpy, vb, "--self-test"], cwd=tk["path"], timeout=600) if os.path.exists(vb) else None
    summary = (t.stderr.strip().splitlines() or [""])[-1]
    tests_ok = t.returncode == 0 and (st is None or st.returncode == 0)
    return wd.record("venv", "done", python=vpy, base_python=py, self_tests_ok=tests_ok,
                     self_tests=clean(summary, 120) + ("" if st is None else f"; verify_backup --self-test exit {st.returncode}"))


def step_keys(args, wd):
    tk, venv = wd.done("toolkit"), wd.done("venv")
    cands = []
    for p in wd.done("pull")["pulled"]:
        out = os.path.join(wd.sub("candidates"), "pid-%d" % p["pid"])
        if os.path.exists(os.path.join(out, "candidate.json")):
            with open(os.path.join(out, "candidate.json")) as f:
                info = json.load(f)
        else:
            r = _run([venv["python"], os.path.join(tk["path"], SCRIPTS, "recover_process_key.py"), "--capture", p["dir"],
                      "--profile", os.path.join(tk["path"], PROFILE), "--output", out], timeout=1800)
            info = _last_json(r.stdout) if r.returncode == 0 else None
            if info is None:
                cands.append({"pid": p["pid"], "ok": False, "error": clean((r.stderr or r.stdout)[-300:], 300)})
                continue
        cands.append({"pid": p["pid"], "ok": True, "file": os.path.join(out, info.get("candidate_file", "master-candidate.bin")),
                      "capture_complete": info.get("capture_complete"), "validation": info.get("validation")})
    ok = any(c["ok"] for c in cands)
    return wd.record("keys", "done" if ok else "failed", candidates=cands,
                     message="" if ok else "no candidate key recovered from the captures")


def _decrypt(venv, tk, copy_root, src, cand, out, expected_sha, marker):
    argv = [venv["python"], os.path.join(tk["path"], SCRIPTS, "decrypt_copy.py"), "--copy-root", copy_root,
            "--input-copy", src, "--master-file", cand, "--output", out]
    if expected_sha:
        argv += ["--expected-sha256", expected_sha]
    if marker:
        argv += ["--expected-marker", marker]
    r = _run(argv, timeout=7200)
    return r.returncode, _last_json(r.stdout), clean((r.stderr or "")[-300:], 300)


def step_sample(s, args, wd, root):
    tk, venv, keys = wd.done("toolkit"), wd.done("venv"), wd.done("keys")
    files = NasFiles(s, root)
    copy_root = wd.sub("copies", "sample")
    name = args.sample.rstrip("/").rsplit("/", 1)[-1]
    src = os.path.join(copy_root, name)
    if not os.path.exists(src):
        files.fetch(args.sample, None, src)
    r = _run([venv["python"], os.path.join(tk["path"], SCRIPTS, "inspect_footer.py"), "--input-copy", src], timeout=600)
    footer = _last_json(r.stdout) if r.returncode == 0 else None
    marker = args.expected_marker
    results, verified = [], None
    for c in keys["candidates"]:
        if not c["ok"]:
            continue
        out = os.path.join(wd.sub("recovered", "sample"), "pid-%d-%s" % (c["pid"], SUFFIX.sub("", name)))
        if os.path.exists(out):
            os.remove(out)
        rc, res, err = _decrypt(venv, tk, copy_root, src, c["file"], out, args.expected_sha256, marker)
        ok = rc == 0 and res is not None
        results.append({"pid": c["pid"], "ok": ok, "output": out if ok else None,
                        "verification": (res or {}).get("verification"), "sha256": (res or {}).get("sha256"),
                        "error": None if ok else err})
        if ok and verified is None:
            verified = c
    note = ""
    if footer and not verified and footer.get("marker") and footer["marker"] != (marker or "ce35a593"):
        note = (f"the copy's session marker is {footer['marker']}; after checking it belongs to this case, run again "
                f"with --expected-marker {footer['marker']}")
    return wd.record("sample", "done" if verified else "failed", copy=src, footer=footer,
                     footer_error=None if footer else clean(r.stderr, 300), results=results,
                     verified_pid=verified["pid"] if verified else None,
                     verified_file=verified["file"] if verified else None,
                     verification=("known-original-sha256" if args.expected_sha256 else "key-record only")
                     if verified else None, message=note or ("" if verified else "no candidate decrypted the sample"))


def step_decrypt(s, args, wd, root):
    tk, venv = wd.done("toolkit"), wd.done("venv")
    sample = wd.done("sample")
    cand = (sample or {}).get("verified_file")
    if not cand:
        if not args.force:
            return wd.record("decrypt", "failed", message="no candidate verified on a --sample yet (override: --force "
                                                          "uses the first candidate)")
        cand = next(c["file"] for c in wd.done("keys")["candidates"] if c["ok"])
    files = NasFiles(s, root)
    real = files.real(args.decrypt_from) if files.local() else ""
    out_root = os.path.abspath(args.decrypt_to)
    os.makedirs(out_root, mode=0o700, exist_ok=True)
    copy_root = wd.sub("copies", "batch")
    prev = wd.state["steps"].get("decrypt") or {}
    counts = {"decrypted": 0, "skipped_existing": 0, "failed": 0, "not_encrypted": 0}
    failures = list(prev.get("failures", []))[-200:]
    for rel, fsp, rp in files.walk(real, args.decrypt_from):
        if not SUFFIX.search(rel):
            counts["not_encrypted"] += 1
            continue
        out = os.path.join(out_root, SUFFIX.sub("", rel))
        if os.path.exists(out):
            counts["skipped_existing"] += 1
            continue
        os.makedirs(os.path.dirname(out), exist_ok=True)
        src = os.path.join(copy_root, rel)
        if not os.path.exists(src):
            files.fetch(fsp, rp, src)
        rc, res, err = _decrypt(venv, tk, copy_root, src, cand, out, None, args.expected_marker)
        if rc == 0:
            counts["decrypted"] += 1
            if not args.keep_copies:
                os.remove(src)
        else:
            counts["failed"] += 1
            failures.append({"file": rel, "error": err})
        if sum(counts.values()) % 25 == 0:
            wd.record("decrypt", "running", counts=counts, failures=failures[-200:], to=out_root)
    return wd.record("decrypt", "done" if counts["failed"] == 0 else "failed", counts=counts, failures=failures[-200:],
                     to=out_root, candidate_pid=(sample or {}).get("verified_pid"),
                     message="" if counts["failed"] == 0 else f"{counts['failed']} file(s) did not decrypt (see failures)")


# --- driver --------------------------------------------------------------------------------------------------

def plan_lines(args) -> list:
    out = []
    if not args.no_contain:
        out.append("contain: freeze the encryptor processes (SIGSTOP)")
    out.append("toolkit: c3rb3r-rescue " + (f"from {args.rescue_dir}" if args.rescue_dir else
                                            f"at {config.get()['incident']['rescue_commit'][:12]}"))
    out.append(f"capture: process memory to {args.capture_dir or '(--capture-dir)'} on the NAS")
    if not args.keep_on_nas:
        out += ["pull: download the capture", "venv + self-tests", "keys: recover candidates"]
    if args.sample:
        out.append(f"sample: decrypt a copy of {args.sample} with each candidate")
    if args.decrypt_from:
        out.append(f"decrypt: copies of {args.decrypt_from} -> {args.decrypt_to}")
    return out


def rescue(s, args, root: str = "", extra: dict | None = None):
    wd = Workdir(args.workdir or default_workdir())
    if not args.capture_dir and not wd.done("capture"):
        raise InputRequired("add --capture-dir /SHARE/folder (a shared folder on a USB disk or another volume than "
                            "the encrypted data)")
    if args.decrypt_from and not args.decrypt_to:
        raise InputRequired("add --decrypt-to DIR (a local folder or external disk for the decrypted copies)")
    lines = [f"Workdir: {wd.path}"]
    if not args.yes:
        lines += ["Plan:"] + [f"  {x}" for x in plan_lines(args)]
        if not can_prompt():
            lines.append("Not applied: add --yes (or NAS_YES=1).")
            return lines, {"workdir": wd.path, "steps": wd.state["steps"], "plan": plan_lines(args)}, InputRequired.exit_code
        sys.stderr.write("Run these steps? [y/N] ")
        sys.stderr.flush()
        if sys.stdin.readline().strip().lower() not in ("y", "yes"):
            return lines + ["Not applied."], {"workdir": wd.path, "steps": wd.state["steps"]}, 1

    wanted = ["contain"] if not args.no_contain else []
    wanted += ["toolkit", "capture"]
    if not args.keep_on_nas:
        wanted += ["pull", "venv", "keys"]
        if args.sample:
            wanted.append("sample")
        if args.decrypt_from:
            wanted.append("decrypt")
    failed = None
    for step in wanted:
        if wd.done(step) and not (step == "decrypt"):
            lines.append(f"{step}: done earlier (resumed)")
            continue
        print(f"rescue: {step}...", file=sys.stderr)
        if step == "contain":
            e = step_contain(s, args, wd, root, extra)
        elif step == "toolkit":
            e = step_toolkit(args, wd)
        elif step == "capture":
            e = step_capture(s, args, wd, root)
        elif step == "pull":
            e = step_pull(s, args, wd, root)
        elif step == "venv":
            e = step_venv(args, wd)
        elif step == "keys":
            e = step_keys(args, wd)
        elif step == "sample":
            e = step_sample(s, args, wd, root)
        else:
            e = step_decrypt(s, args, wd, root)
        lines.append(f"{step}: {e['status']}" + (f" - {e['message']}" if e.get("message") else ""))
        lines += _detail(step, e)
        if e["status"] != "done":
            failed = step
            break
    steps = wd.state["steps"]
    nxt = _next_steps(args, wd, failed)
    lines.append("Next steps:")
    lines += [f"  {i}. {t}" for i, t in enumerate(nxt, 1)]
    data = {"workdir": wd.path, "steps": steps, "failed_step": failed, "next_steps": nxt}
    return lines, data, (0 if failed is None else 1)


def _detail(step, e) -> list:
    out = []
    if step == "contain":
        out.append(f"  frozen PIDs: {', '.join(map(str, e.get('frozen', []))) or '-'}")
    if step == "toolkit" and e.get("commit"):
        out.append(f"  {e['path']} at {e['commit']}" + ("" if e.get("commit_matches", True) else
                                                        f" (pinned {e.get('pinned')})"))
    if step == "capture":
        for c in e.get("captures", []):
            sha = (c.get("inspect") or {}).get("exe_sha256")
            out.append(f"  pid {c['pid']}: exit {c.get('exit')}, " + (
                f"complete {(c.get('summary') or {}).get('complete')}, exe sha256 {sha} "
                f"({'matches' if c.get('reviewed_sha256_match') else 'differs from'} the reviewed sample)"
                if sha else clean(c.get("error"), 160)))
    if step == "keys":
        for c in e.get("candidates", []):
            out.append(f"  pid {c['pid']}: " + (f"candidate stored ({c['file']}, mode 400)" if c["ok"] else c["error"]))
    if step == "sample":
        for r in e.get("results", []):
            out.append(f"  candidate pid {r['pid']}: " + (f"decrypted -> {r['output']} ({r['verification']})"
                                                          if r["ok"] else f"failed: {r['error']}"))
    if step == "decrypt" and e.get("counts"):
        out.append("  " + ", ".join(f"{k} {v}" for k, v in e["counts"].items()) + f" -> {e.get('to')}")
    return out


def _next_steps(args, wd, failed) -> list:
    st = wd.state["steps"]
    if failed == "capture" and (st.get("capture") or {}).get("same_volume"):
        return [f"Plug a USB disk into the NAS (or pick a share on another volume) and run again with "
                f"--capture-dir /usbshareN/rescue --workdir {wd.path}", "Keep the NAS running and the processes frozen."]
    if failed:
        return [f"Fix what step {failed} reports, then run the same command again with --workdir {wd.path} (finished "
                "steps are kept)", "Keep the NAS running and the processes frozen until the capture is done."]
    out = []
    if args.keep_on_nas:
        out.append(f"The capture is on the NAS at {(st.get('capture') or {}).get('fs_case_dir')}; copy it to a clean "
                   f"analysis machine, then run again without --keep-on-nas (--workdir {wd.path})")
    elif not args.sample:
        out.append(f"Test the candidates on one encrypted file: --sample /SHARE/path/file.L0CK3D "
                   f"[--expected-sha256 ORIGINAL] --workdir {wd.path}")
    elif not args.decrypt_from:
        out.append(f"Decrypt copies: --decrypt-from /SHARE/folder --decrypt-to /external/disk --workdir {wd.path}")
    out.append("Keep the ciphertext on the NAS until the decrypted copies are checked (open them; compare hashes "
               "with any known originals)")
    out.append("Release the frozen processes after the capture: nas incident contain --release")
    return out
