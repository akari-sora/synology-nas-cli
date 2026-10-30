"""`nas incident rescue`: recover C3RB3R / .L0CK3D file keys from the encryptor's memory, end to end.

Orchestrates the community toolkit c3rb3r-rescue (fetched at run time at a pinned commit; none of its code
is part of this repository) with this CLI's own pieces:

  contain   freeze the encryptor processes (nas incident contain --yes) unless --no-contain
  toolkit   clone c3rb3r-rescue at incident.rescue_commit and verify the SHA (or --rescue-dir: a clean
            checkout at that commit; --force-unpinned-toolkit for any other)
  capture   on the NAS as root: the toolkit's capture_process_memory.py `inspect` + `capture` for every
            frozen PID into a new case folder under --capture-dir (a different volume or USB disk than
            the encrypted data, compared by mount source; --force-same-volume for the same one); exe hash
            compared with the reviewed one; the case folder is handed to the signed-in DSM account
  pull      download the capture to the local workdir (free space checked; skip with --keep-on-nas)
  venv      a venv in the workdir with the toolkit's pinned requirements (pip --require-hashes with the
            hashes in REQUIREMENT_HASHES); its self-tests
  keys      recover_process_key.py on every capture -> candidates (files mode 400, never printed)
  sample    --sample NAS_FILE: copy, inspect_footer.py, decrypt_copy.py with each candidate
  decrypt   --decrypt-from NAS_FOLDER --decrypt-to DIR: copies decrypted with the verified candidate
            (--force-unverified-key: the first candidate without a verified --sample)

--force means all three --force-* flags.

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
import secrets
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

CAPTURE_TIMEOUT = 14400  # seconds for one process's capture
INSPECT_TIMEOUT = 600

CAPTURE = r'''
import base64, glob, hashlib, json, os, re, subprocess, sys, time
OUT, TOKEN, CFG = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
R = CFG.get("root", "")
RR = os.path.realpath(R) if R else ""
res = {"marker": TOKEN, "version": 1, "errors": [], "captures": [], "case_dir": None, "same_volume": None,
       "capture_source": None, "owner": None}
tool = None


def full(p):
    return R + p if R and not p.startswith(R) else p


def nas_path(real):
    if RR and (real == RR or real.startswith(RR + "/")):
        return real[len(RR):] or "/"
    return real


def resolves_to_itself(p):
    # p (full path) and every existing parent resolve to themselves: no symlink on the way
    e = p
    while not os.path.lexists(e) and os.path.dirname(e) != e:
        e = os.path.dirname(e)
    want = RR + os.path.normpath(e)[len(R):] if R else os.path.normpath(e)
    return os.path.realpath(e) == want


def mounts():
    out = []
    try:
        with open(R + "/proc/self/mountinfo") as f:
            for line in f:
                x = line.split()
                if "-" in x[6:]:
                    i = x.index("-", 6)
                    mp = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), x[4])
                    out.append((mp, x[i + 2] if len(x) > i + 2 else "", x[i + 1]))
    except (OSError, IndexError):
        pass
    return out


MOUNTS = mounts()


def source(p):
    # the device a path is stored on: mount source of the longest mount point above its real path
    # (Btrfs subvolumes, e.g. every shared folder, have their own st_dev but share the volume's source)
    rp = nas_path(os.path.realpath(full(p)))
    best = None
    for mp, src, fs in MOUNTS:
        if mp == "/" or rp == mp or rp.startswith(mp.rstrip("/") + "/"):
            if best is None or len(mp) > len(best[0]):
                best = (mp, src, fs)
    if best:
        return best[1]
    try:
        return "st_dev:%d" % os.stat(full(p)).st_dev
    except OSError:
        return None


try:
    cap = full(CFG["capture_dir"])
    if not resolves_to_itself(cap):
        raise ValueError("capture dir %s has a symlink in its path" % CFG["capture_dir"])
    affected = {}
    for p in CFG.get("affected_paths") or []:
        src = source(p)
        if src:
            affected.setdefault(src, p)
    if not affected:
        for v in sorted(glob.glob(R + "/volume[0-9]*")):
            src = source(v)
            if src:
                affected.setdefault(src, nas_path(os.path.realpath(v)))
    os.makedirs(cap, mode=0o700, exist_ok=True)
    if not resolves_to_itself(cap):
        raise ValueError("capture dir %s has a symlink in its path" % CFG["capture_dir"])
    res["capture_source"] = source(cap)
    if res["capture_source"] in affected:
        res["same_volume"] = affected[res["capture_source"]]
    if not res["same_volume"] or CFG.get("force"):
        case = os.path.join(cap, CFG["case"])
        os.mkdir(case, 0o700)
        res["case_dir"] = case
        if CFG.get("tool_path"):  # uploaded to the staging folder: used only if its hash matches
            fd = os.open(CFG["tool_path"], os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as f:
                body = f.read()
            if hashlib.sha256(body).hexdigest() != CFG["tool_sha256"]:
                raise ValueError("the staged capture tool's sha256 differs from the uploaded file")
        else:
            body = base64.b64decode(CFG["tool_b64"])
        tool = os.path.join(case, ".capture_process_memory.py")
        fd = os.open(tool, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        os.write(fd, body)
        os.close(fd)
        for pid in CFG["pids"]:
            item = {"pid": pid}
            res["captures"].append(item)
            try:
                ins = subprocess.run([sys.executable, "-I", "-B", tool, "inspect", "--pid", str(pid)],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     timeout=CFG.get("inspect_timeout", 600))
                if ins.returncode != 0:
                    item.update(error="inspect: " + ins.stderr.decode("utf-8", "replace")[-400:])
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
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   timeout=CFG.get("timeout", 14400))
                item.update(exit=c.returncode, output=out, stderr=c.stderr.decode("utf-8", "replace")[-400:])
                lines = [l for l in c.stdout.decode("utf-8", "replace").splitlines() if l.strip().startswith("{")]
                if lines:
                    try:
                        item["summary"] = json.loads(lines[-1])
                    except ValueError:
                        pass
            except Exception as e:
                item["error"] = "%s: %s" % (type(e).__name__, e)
        os.remove(tool)
        tool = None
        owner = CFG.get("owner")
        if owner:
            # File Station lists and downloads as the signed-in account: the case folder becomes its own
            p = subprocess.run(["id", "-u", owner], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            uid = int(p.stdout.decode().strip()) if p.returncode == 0 else None
            if uid is None:
                res["errors"].append("id -u %s: %s" % (owner, p.stderr.decode("utf-8", "replace").strip()[-200:]))
            else:
                for dirpath, dirs, files in os.walk(case):
                    for n in [dirpath] + [os.path.join(dirpath, f) for f in files]:
                        if not os.path.islink(n):
                            os.lchown(n, uid, -1)
                            os.chmod(n, (os.stat(n).st_mode & 0o777) | (0o700 if n == dirpath else 0o400))
                res["owner"] = {"name": owner, "uid": uid}
except Exception as e:
    res["errors"].append("%s: %s" % (type(e).__name__, e))
finally:
    if tool and os.path.exists(tool):
        os.remove(tool)
    if CFG.get("tool_path") and os.path.lexists(CFG["tool_path"]):
        os.remove(CFG["tool_path"])
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


def forced(args, flag: str) -> bool:
    """--force-same-volume / --force-unverified-key / --force-unpinned-toolkit, or --force for all of them."""
    return bool(getattr(args, "force", False) or getattr(args, flag, False))


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
                    if os.path.islink(rp):
                        continue
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
        st = _run(["git", "-C", path, "status", "--porcelain"], timeout=60) if head else None
        dirty = [l for l in (st.stdout.splitlines() if st is not None and st.returncode == 0 else ["(git status failed)"])
                 if l.strip()]
        if (head != want or dirty) and not forced(args, "force_unpinned_toolkit"):
            why = (f"HEAD is {head or 'not a git checkout'}, the pinned commit is {want}" if head != want else
                   f"{len(dirty)} changed or untracked file(s): " + ", ".join(clean(l, 80) for l in dirty[:5]))
            return wd.record("toolkit", "failed", path=path, commit=head, pinned=want, changed=dirty[:50],
                             message=f"--rescue-dir {path}: {why} (override: --force-unpinned-toolkit)")
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
                     unpinned_override=bool(args.rescue_dir) and forced(args, "force_unpinned_toolkit"),
                     reviewed_sha256={"packed": prof.get("packed_sha256"), "unpacked": prof.get("unpacked_sha256")})


def _stage_file(s, name: str, body: bytes) -> tuple:
    """Upload `body` as deploy.stage_dir/name; (File Station path, path on the NAS's disk)."""
    import tempfile
    from .selfmon import _stage
    stage, stage_fs = _stage(s)
    s.call("SYNO.FileStation.CreateFolder", "create", version=2, params={
        "folder_path": json.dumps([stage.rsplit("/", 1)[0] or "/"]), "name": json.dumps([stage.rsplit("/", 1)[1]]),
        "force_parent": True})
    tmpdir = tempfile.mkdtemp(prefix="nas-rescue-")
    try:
        with open(os.path.join(tmpdir, name), "wb") as f:  # File Station keeps the local file name
            f.write(body)
        up = s.upload("SYNO.FileStation.Upload", "upload", 2,
                      {"path": stage, "create_parents": "true", "overwrite": "true"}, os.path.join(tmpdir, name))
    finally:
        shutil.rmtree(tmpdir)
    if not up.get("ok"):
        raise NasError(f"upload to {stage} failed: {up.get('error')}")
    return f"{stage}/{name}", f"{stage_fs}/{name}"


def step_capture(s, args, wd, root):
    tk = wd.done("toolkit")
    pids = sorted(set((wd.done("contain") or {}).get("frozen", []) + list(args.pid or [])))
    if not pids:
        return wd.record("capture", "failed", message="no PID to capture: run with containment or --pid N")
    files = NasFiles(s, root)
    real = files.real(args.capture_dir)
    with open(os.path.join(tk["path"], SCRIPTS, "capture_process_memory.py"), "rb") as f:
        tool = f.read()
    case = "case-" + dt.datetime.now().strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(3)
    owner = getattr(getattr(s, "backend", None), "account", None) if s.backend_name == "password" else None
    cfg = {"root": root, "capture_dir": real, "case": case, "pids": pids,
           "force": forced(args, "force_same_volume"), "owner": owner,
           "affected_paths": (wd.done("contain") or {}).get("evidence", []),
           "timeout": CAPTURE_TIMEOUT, "inspect_timeout": INSPECT_TIMEOUT}
    staged = None
    if s.backend_name == "local" or root:
        cfg["tool_b64"] = base64.b64encode(tool).decode()
    else:  # DSM refuses long task scripts (4803): the tool goes through the staging folder, checked by sha256
        staged, cfg["tool_path"] = _stage_file(s, f"nas-rescue-tool-{secrets.token_hex(6)}.py", tool)
        cfg["tool_sha256"] = hashlib.sha256(tool).hexdigest()
    try:
        d = run_root_python(s, CAPTURE, cfg, "nas-incident-rescue", "capture script", root=root,
                            timeout=len(pids) * (CAPTURE_TIMEOUT + INSPECT_TIMEOUT) + 600)
    finally:
        if staged:
            s.call("SYNO.FileStation.Delete", "start", version=2, params={"path": json.dumps([staged]),
                                                                          "recursive": False})
    if d.get("errors") and not d.get("case_dir"):
        return wd.record("capture", "failed", errors=d["errors"], message="; ".join(clean(e, 200) for e in d["errors"]))
    if d.get("same_volume") and not forced(args, "force_same_volume"):
        return wd.record("capture", "failed", same_volume=d["same_volume"], capture_source=d.get("capture_source"),
                         message=(f"{args.capture_dir} is on the same volume as the encrypted data "
                                  f"({d['same_volume']}, {d.get('capture_source')}): use a USB disk or another volume "
                                  "(override: --force-same-volume)"))
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
                     same_volume=d.get("same_volume"), capture_source=d.get("capture_source"), owner=d.get("owner"),
                     errors=d.get("errors", []),
                     message="" if ok else "no capture finished (see captures[].error / stderr)")


PULL_MARGIN = 256 << 20


def step_pull(s, args, wd, root):
    cap = wd.done("capture")
    files = NasFiles(s, root)
    hint = (f"move {wd.path} (it holds state.json) to a folder with room, e.g. on /volumeN, and run the same command "
            "with --workdir NEW_PATH; or run with --keep-on-nas to stop after the capture")
    if s.backend_name == "local" and os.stat(wd.path).st_dev == os.stat("/").st_dev:
        return wd.record("pull", "failed", message=f"the workdir {wd.path} is on the NAS's system partition (/): {hint}")
    need = sum((c.get("inspect") or {}).get("readable_bytes") or 0 for c in cap["captures"] if c.get("exit") in (0, 2))
    free = shutil.disk_usage(wd.path).free
    if need and free < need + PULL_MARGIN:
        return wd.record("pull", "failed", need_bytes=need, free_bytes=free, message=(
            f"the capture needs about {need >> 20} MiB in {wd.path}, {free >> 20} MiB free: {hint}"))
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
    with open(os.path.join(tk["path"], "requirements.txt")) as f:
        lines, unknown = hashed_requirements(f.read())
    if unknown and not forced(args, "force_unpinned_toolkit"):
        return wd.record("venv", "failed", python=vpy, unknown_pins=unknown, message=(
            "requirements.txt pins without known hashes: " + ", ".join(clean(u, 60) for u in unknown[:5])
            + f" (hashes are kept for the toolkit at {REQUIREMENTS_FOR[:12]}; override: --force-unpinned-toolkit "
            "installs them without hash checks)"))
    if unknown:
        req, hashed = os.path.join(tk["path"], "requirements.txt"), False
    elif lines:
        req, hashed = os.path.join(wd.path, "requirements-hashed.txt"), True
        with open(req, "w") as f:
            f.write("\n".join(lines) + "\n")
    else:
        req, hashed = None, False
    if req:
        r = _run([vpy, "-m", "pip", "install", "--disable-pip-version-check", "--quiet", "--no-input"]
                 + (["--require-hashes"] if hashed else []) + ["-r", req], timeout=1800)
        if r.returncode != 0:
            return wd.record("venv", "failed", python=vpy, message=f"pip install -r {os.path.basename(req)}: "
                             + clean(r.stderr[-400:], 400))
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([os.path.join(tk["path"], SCRIPTS), os.path.join(tk["path"], "scripts")]))
    t = _run([vpy, "-m", "unittest", "discover", "-s", "tests"], cwd=tk["path"], env=env, timeout=1800)
    vb = os.path.join(tk["path"], SCRIPTS, "verify_backup.py")
    st = _run([vpy, vb, "--self-test"], cwd=tk["path"], timeout=600) if os.path.exists(vb) else None
    summary = (t.stderr.strip().splitlines() or [""])[-1]
    tests_ok = t.returncode == 0 and (st is None or st.returncode == 0)
    return wd.record("venv", "done", python=vpy, base_python=py, self_tests_ok=tests_ok, hashed_requirements=hashed,
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
                last = ((r.stderr or r.stdout or "").strip().splitlines() or [""])[-1]  # the exception line
                cands.append({"pid": p["pid"], "ok": False, "error": clean(last, 300)})
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
        if not forced(args, "force_unverified_key"):
            return wd.record("decrypt", "failed", message="no candidate verified on a --sample yet (override: "
                                                          "--force-unverified-key uses the first candidate)")
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


# --- hashes for the toolkit's requirements.txt ---------------------------------------------------------------
# requirements.txt at REQUIREMENTS_FOR pins numpy and cryptography; cffi and pycparser are cryptography's
# dependencies (pip --require-hashes needs every package). Every file PyPI lists for each version, so the
# wheel for any platform (or the sdist) matches. Source: https://pypi.org/pypi/NAME/VERSION/json.
REQUIREMENTS_FOR = "ef18b9980cccfe8326b16557c6b48933a80e0c99"
REQUIREMENT_HASHES = {
    "numpy==2.3.5": (  # 74 files
        "00dc4e846108a382c5869e77c6ed514394bdeb3403461d25a829711041217d5b",
        "0472f11f6ec23a74a906a00b48a4dcf3849209696dff7c189714511268d103ae",
        "04822c00b5fd0323c8166d66c701dc31b7fbd252c100acd708c48f763968d6a3",
        "052e8c42e0c49d2575621c158934920524f6c5da05a1d3b9bab5d8e259e045f0",
        "09a1bea522b25109bf8e6f3027bd810f7c1085c64a0c7ce050c1676ad0ba010b",
        "0cd00b7b36e35398fa2d16af7b907b65304ef8bb4817a550e06e5012929830fa",
        "0d8163f43acde9a73c2a33605353a4f1bc4798745a8b1d73183b28e5b435ae28",
        "1062fde1dcf469571705945b0f221b73928f34a20c904ffb45db101907c3454e",
        "11e06aa0af8c0f05104d56450d6093ee639e15f24ecf62d417329d06e522e017",
        "17531366a2e3a9e30762c000f2c43a9aaa05728712e25c11ce1dbe700c53ad41",
        "1978155dd49972084bd6ef388d66ab70f0c323ddee6f693d539376498720fb7e",
        "1ed1ec893cff7040a02c8aa1c8611b94d395590d553f6b53629a4461dc7f7b63",
        "2dcd0808a421a482a080f89859a18beb0b3d1e905b81e617a188bd80422d62e9",
        "2e2eb32ddb9ccb817d620ac1d8dae7c3f641c1e5f55f531a33e8ab97960a75b8",
        "2feae0d2c91d46e59fcd62784a3a83b3fb677fead592ce51b5a6fbb4f95965ff",
        "3095bdb8dd297e5920b010e96134ed91d852d81d490e787beca7e35ae1d89cf7",
        "30bc11310e8153ca664b14c5f1b73e94bd0503681fcf136a163de856f3a50139",
        "3101e5177d114a593d79dd79658650fe28b5a0d8abeb8ce6f437c0e6df5be1a4",
        "396084a36abdb603546b119d96528c2f6263921c50df3c8fd7cb28873a237748",
        "3997b5b3c9a771e157f9aae01dd579ee35ad7109be18db0e85dbdbe1de06e952",
        "414802f3b97f3c1eef41e530aaba3b3c1620649871d8cb38c6eaff034c2e16bd",
        "51c1e14eb1e154ebd80e860722f9e6ed6ec89714ad2db2d3aa33c31d7c12179b",
        "51c55fe3451421f3a6ef9a9c1439e82101c57a2c9eab9feb196a62b1a10b58ce",
        "5ee6609ac3604fa7780e30a03e5e241a7956f8e2fcfe547d51e3afa5247ac47f",
        "612a95a17655e213502f60cfb9bf9408efdc9eb1d5f50535cc6eb365d11b42b5",
        "6203fdf9f3dc5bdaed7319ad8698e685c7a3be10819f41d32a0723e611733b42",
        "63c0e9e7eea69588479ebf4a8a270d5ac22763cc5854e9a7eae952a3908103f7",
        "66f85ce62c70b843bab1fb14a05d5737741e74e28c7b8b5a064de10142fad248",
        "6cf9b429b21df6b99f4dee7a1218b8b7ffbbe7df8764dc0bd60ce8a0708fed1e",
        "70b37199913c1bd300ff6e2693316c6f869c7ee16378faf10e4f5e3275b299c3",
        "727fd05b57df37dc0bcf1a27767a3d9a78cbbc92822445f32cc3436ba797337b",
        "74ae7b798248fe62021dbf3c914245ad45d1a6b0cb4a29ecb4b31d0bfbc4cc3e",
        "784db1dcdab56bf0517743e746dfb0f885fc68d948aba86eeec2cba234bdf1c0",
        "86945f2ee6d10cdfd67bcb4069c1662dd711f7e2a4343db5cecec06b87cf31aa",
        "86d835afea1eaa143012a2d7a3f45a3adce2d7adc8b4961f0b362214d800846a",
        "872a5cf366aec6bb1147336480fef14c9164b154aeb6542327de4970282cd2f5",
        "8b973c57ff8e184109db042c842423ff4f60446239bd585a5131cc47f06f789d",
        "8cba086a43d54ca804ce711b2a940b16e452807acebe7852ff327f1ecd49b0d4",
        "8f7f0e05112916223d3f438f293abf0727e1181b5983f413dfa2fefc4098245c",
        "900218e456384ea676e24ea6a0417f030a3b07306d29d7ad843957b40a9d8d52",
        "93eebbcf1aafdf7e2ddd44c2923e2672e1010bddc014138b229e49725b4d6be5",
        "9c75442b2209b8470d6d5d8b1c25714270686f14c749028d2199c54e29f20b4d",
        "9ee2197ef8c4f0dfe405d835f3b6a14f5fee7782b5de51ba06fb65fc9b36e9f1",
        "a414504bef8945eae5f2d7cb7be2d4af77c5d1cb5e20b296c2c25b61dff2900c",
        "a4b9159734b326535f4dd01d947f919c6eefd2d9827466a696c44ced82dfbc18",
        "a80afd79f45f3c4a7d341f13acbe058d1ca8ac017c165d3fa0d3de6bc1a079d7",
        "aa5bc7c5d59d831d9773d1170acac7893ce3a5e130540605770ade83280e7188",
        "acfd89508504a19ed06ef963ad544ec6664518c863436306153e13e94605c218",
        "aeffcab3d4b43712bb7a60b65f6044d444e75e563ff6180af8f98dd4b905dfd2",
        "afaffc4393205524af9dfa400fa250143a6c3bc646c08c9f5e25a9f4b4d6a903",
        "b0c7088a73aef3d687c4deef8452a3ac7c1be4e29ed8bf3b366c8111128ac60c",
        "b46b4ec24f7293f23adcd2d146960559aaf8020213de8ad1909dba6c013bf89c",
        "b501b5fa195cc9e24fe102f21ec0a44dffc231d2af79950b451e0d99cea02234",
        "bf06bc2af43fa8d32d30fae16ad965663e966b1a3202ed407b84c989c3221e82",
        "c804e3a5aba5460c73955c955bdbd5c08c354954e9270a2c1565f62e866bdc39",
        "c8a9958e88b65c3b27e22ca2a076311636850b612d6bbfb76e8d156aacde2aaf",
        "cc0a57f895b96ec78969c34f682c602bf8da1a0270b09bc65673df2e7638ec20",
        "cc8920d2ec5fa99875b670bb86ddeb21e295cb07aa331810d9e486e0b969d946",
        "ccc933afd4d20aad3c00bcef049cb40049f7f196e0397f1109dba6fed63267b0",
        "ce581db493ea1a96c0556360ede6607496e8bf9b3a8efa66e06477267bc831e9",
        "d0f23b44f57077c1ede8c5f26b30f706498b4862d3ff0a7298b8411dd2f043ff",
        "d21644de1b609825ede2f48be98dfde4656aefc713654eeee280e37cadc4e0ad",
        "d6889ec4ec662a1a37eb4b4fb26b6100841804dac55bd9df579e326cdc146227",
        "de5672f4a7b200c15a4127042170a694d4df43c992948f5e1af57f0174beed10",
        "e6a0bc88393d65807d751a614207b7129a310ca4fe76a74e5c7da5fa5671417e",
        "ed89927b86296067b4f81f108a2271d8926467a8868e554eaf370fc27fa3ccaf",
        "ee3888d9ff7c14604052b2ca5535a30216aa0a58e948cdd3eeb8d3415f638769",
        "f0963b55cdd70fad460fa4c1341f12f976bb26cb66021a5580329bd498988310",
        "f16417ec91f12f814b10bafe79ef77e70113a2f5f7018640e7425ff979253425",
        "f28620fe26bee16243be2b7b874da327312240a7cdc38b769a697578d2100013",
        "f4255143f5160d0de972d28c8f9665d882b5f61309d8362fdd3e103cf7bf010c",
        "ffac52f28a7849ad7576293c0cb7b9f08304e8f7d738a8cb8a90ec4c55a998eb",
        "ffe22d2b05504f786c867c8395de703937f934272eb67586817b46188b4ded6d",
        "fffe29a1ef00883599d1dc2c51aa2e5d80afe49523c261a74933df395c15c520",
    ),
    "cryptography==50.0.2": (  # 59 files
        "0ddc924c04591c2811ca024d62ecad4f7f6f08af8939c211438f48a16bd23602",
        "0ec5f09541743261e66e291b4a0cbf0fb2997aeaab6d9e9c740b9dba1b58d1c2",
        "0ecbc5652bdb6fc9eaf89a7d196e20941adfe812f43bc4ca05d9150496821047",
        "1981f1db4630889b9ef7803fadef12b056f428cb6b85c27ba57b774793b6093c",
        "1ba34f04897fcdaa73f74145c25f3ec146fbd56593853e88adc2e811303c5f42",
        "241449bf940a5d27309bd317e6f9a2af6932113818bb2b8f5c59ddc7ef16da18",
        "25784ce8b9621c90c643efb9e1e2162ab3b0224cae446ad5e70e7fcb1ce18b51",
        "3dc4fd8058cea1644971207d530e1a03a184a805ffc8ebdddf0599d78a331b81",
        "4061c0079120205fb760c58acab6443e217307dcf05e3702cf970e0689972856",
        "4a20ce1e5cb4284a86692fdcba7cb8754185c6b2e5c56fcef3751cf451d3cdc2",
        "4e81d95e5bafc2d6e34e4bed780e53e4d5b9a2f928573428aa4d35fbec1eb0de",
        "58a0c478eeca76fe5e07993c5a0703def34a6dc6a0cda4f5564639b33112ffe7",
        "58ddb5a8e3179d12f19e4ea34d2d32e9d63a4baa142c875c1eb59f41b7243acd",
        "630ebfea3bf689d075f82316324ff7433dc447fe6bc1bfc76524b74b4a9567d2",
        "6f8700550aa1474a91e5dc07049c46f98b423b5b1ddd0483e0b51362eeeaf5be",
        "78198641e5be9521beea5aa782bb551a58068d10e6eb04c9c680c1b69f2e7d45",
        "79def8d059362e7831389ed3be0ecdf58a89386e1271e35dd9f5af84e81bffd0",
        "7a8701d6b584d76e909e3d305b7d126b41439876a5aaf76cddc67fc230eafa2e",
        "7afa5a6602a9f29af1f3a2965f831bae7c9d5d597b7cbb716d41ab3b7d89879c",
        "7b46165bb56eb4704e2eaaf86f3c940d19154535d9b0ca7d6d590b04060e00d5",
        "7b75de3c8b3be1cdb1052747c929440c3eea46c1bc2cb8a6e3a48388e9b7b452",
        "7c6d0330c472d96f6a6afe24d80dfdf15176c33096f0a4397ae4c60f3dd3be48",
        "828d49b0ff5a0e3975865571c5d91dbbdd0d38d8289b249a163e9425413a5e05",
        "84f964e537f916e2cc85199e5a88742e964939b575ac8598b3f9d6cc416cdaf1",
        "85d0d9a31b9098e98534226d5686b47264b95e62ce459dc2e62fdfc809f9fe93",
        "87e9ce85beb6b328ba370cc6e6aea483c92617b4c95b1d33a49297eb662bfb04",
        "8c71ba2cd31fc93748c38e1b613200ff1c2665cbfd5341fe3a61cfde35a1430e",
        "92e665960f25fcdc73725b9cec7a3824f279ba97a98653afe9ffac2e43668f67",
        "94e5e9f108ee10471288214d3d233fbfbb492840a8457eb85178d643ddeb32c7",
        "9c8402a82ea0dc4ceeab793db05f0fafa8ca139ca34fcde5df0f596103c74107",
        "9dab55f57c74c3cad24c323bacbbd04be4705ba6eb0d92e920b1fc4837ed5079",
        "a582ab2ae1d34f67112cadc86702774c9ea4374df6bca6afe672817203c99134",
        "a6557e5f38e065ca9fbdaf7cfc7435ecb1d113aa81a022d1b51921ee7432e227",
        "a9f7355e6fab51f6c369b86fb7571cffa05edee2c2121e0380a37fb9ac1cd5c1",
        "ab50ee449bf968271e820086f10a33d101dd060370abc10bcd22279be2656539",
        "ac9ed99d81760c62fe89d5f0815cdfa1ba9a35141cf30f1c2d044f04b4803d2e",
        "b13478603dcd0a2479ff8e87e2c19a7d525734686fe3c49542472293a204212d",
        "c423ab384a46c4dff7217b2ea5ba2e11cffdeab6441acd04cf65a369caf0366c",
        "c5e67125c7dca78d199ec4e116aa93dbb83494808ecbb8211a2cb09b1bf41dbd",
        "c71be1cbfa5cd9a41ee452acf1eccd82b2c05950358b106ec8ceb83411d1a020",
        "cbc8738fd8526d80f35cb3a40d41f41a2e7030bb3b18b09a6778ef63d291c2fd",
        "ce47f66801c20ec6c6632453bb5960fe38939e9306970b48b3a5a26de7745d94",
        "d370b8d1dfcdf7130178137f6fbee6140774a1acc6cacefc4b42643ec11d0a3a",
        "d38cdff612d06fa6a32840d5e1b1f7a27cee4a349aa9085d94a67789d6bfd408",
        "d8947001be83df1394050758ce0e745dd74fb134eef0a4b5124208dfc3a68c37",
        "deb9fde5c60e437ee4821bc9bc39ff31b42135c27e1dc61ef0a629389c1de62e",
        "dfe9763530994147d9af1def057a5b9658b00e8f8fe8743d144d1e0911c2e454",
        "e105ab60406787da31fccc883fc0f733af1efd78f0136a4599692c4083a73d0c",
        "e275096ea1e60cc595cda2836fd4a6c725d1125108b868be17f53684d164e2cc",
        "edc3342adf8f697fc5f59c887a304356f147b397809440ed64e2fa6af2f50f37",
        "ee247f5c245c9a2fe7c8e2214e295918838e44e00a45a6718451e4004219e767",
        "eef4c2f3423810b3070ab391f85436d2f8bbfcb286ac15cbc73190b3563b1f1a",
        "f21e8a22c8605750c7af886bab299a363721264061b4ac0a30efb73cfd58efc5",
        "f265528741e048bce55c3463ed721fb0aa45a5888d8add8cfeccb3035451bbdc",
        "f2f9bd7f90c64fe89253f0a2c05e3c4856072660429ce8831b4235bf29403a67",
        "f785f6161f202ab04d8ca194158968798e480ca058943907972da5f12e2881e8",
        "f9f6143a8c75945eb960d9eb98905a441394abfa24afaae239d514ffb2586480",
        "fa8f5efb344d6908a1ce62f4a24e2e5780f825d6f53f5f50ec5ffacac72936cb",
        "fdd28f912fccfec1846a94e2e1e8f9b0012f557f0c46fe4f3eb0d7a87afcf90b",
    ),
    "cffi==2.1.1": (  # 100 files
        "046bfc24911b37851ee1b51aab8bffe713d89c68c6a057b09484ce9fd5f69b4e",
        "06c72bb76605a4b0cd0aad6930b69d4baf7dd5d806cfc409b824191099700e66",
        "0beceaabe56af686895136a2de78db54ecd8e4046b236b8fd6d6cb61389e9bf2",
        "154852545011f779917b11c78db2358d095da62a9a172b78ad0a583ee5adc0d0",
        "194cffa889098ced9976c3fc6340305e43f6303657d298da55366907c05c22d6",
        "19ee6127ee34de7d83ce3d371ebc5ed91addbdcc39f9ab15ce4eb35a4e534971",
        "1a18a57b58cfb21fc28d72e876acf10eaed67a1ed96226f92af4df681d571c4c",
        "1aa5645c30469b09530c4ebca77ebf8f17618293c58f8549cb1a543a50236e7d",
        "1dea0e4d7d4f11f619fe8c1d76caf49e24405b4b5743c0e3be16a500ecd930c9",
        "208f941bb9d18e768138677f0a6d2ce01f590df56043dda1df1535ac57c88517",
        "210019b6c7cf07f081b4c54635c8cf744377001350e29cc0f81c4377b4797735",
        "246fa40ce8645a614ff682e0b70f37134e460eaf93a775e0cbe3cca585a67a80",
        "25792eac27877609e7bb06d42ff88278a6624fff2ba9bbb523c09616b117e80f",
        "27350daa11d4f10c540e6e89dada4c54feb7256ad03e9a4dc075ebad7ba360d1",
        "28907ab9bfb6aa13184cfc17c6b8e1023c5ab6fd7076d8c20a35e59fe04f8f29",
        "2ae64be792b8966f2c69538199728b290e34726562896df1e5dc8ffd8d8188e8",
        "31348097ff5bbe827ccc41795d4dd099d9f0625e7def00ee653c137a490c2a6c",
        "3143d81e29e1e20a9ce10901ec369012947876596f75a222235965f2b7ae832e",
        "3222ba5d678f80a030e6afbcc33dc1ae5cb45facabb61cee2c7016b8432fde48",
        "3311ed60d36f83378794e1009ac6258bafbf81f7888b4caa7b35a521e3f95813",
        "334644fbac4eff73d985a17a91226df55d0f394160c4cfb880e084c8f7161cac",
        "34e261f78cb6ceaaa36f42f2613f4380d94d9c759a9c73c769ee6e0247364632",
        "363e05fa78e15116c3c32c210ee36884fd6b9afa6d440e47112c3bd511d64cb6",
        "398aff33cee2767e3e781d2554c54bd0dff386bb437581e0d8011fde1a942ec1",
        "3d22a20b1fb1632cc72c22f95f7b0d2961c3e1c235f245ba4c606c4771035659",
        "42a494cee34437f05546455144f2b5d9ac09b1face62bcfce597d2e521066688",
        "42e2f76b9455f5a9a844f770bf3e200ed3da0e15f5df3db9c31fe80b04b3d004",
        "42f6930c31dc7f50732c9ae793c2786c7b6b044195967bbdde40bb9be81c4cc0",
        "456a61fa52d579ebf9df2e9552ead5129855dbaff6c1e5a9b1bc408809bdc062",
        "471cee653ae88de62096552e6d24ccb4a5adb8c8c9f10b5054d0122c15bf2779",
        "49cbc70e6542d4ccccb936558d1064a8012541e78f821f955cff24e357776c94",
        "4a7c934f7360e8cd64fe9efadcbd10c7c6364f531e432b9a4bf5ccbc9e0e8b50",
        "4be96343e422f2dfcd12ab5c9f5aebe03f82f737c6bffeca6830b3875cb44aab",
        "4f42141fc14250de6dde5ee7ea4432be017252d91f19c5ad043c084cea629cac",
        "507a24c282e0f42f8ed737cf048572cbf580468da5555764a8331735e9c736b6",
        "51b31d1c98274844cfd7838ce00bfc27c7423a4dc00fc0772fc3331c2cc90676",
        "58acb8ab8e295e6c5ea12f888cbb13cf21511ef2a3303a23f4325c29d17fe5c1",
        "5a59cc1c4442bc3d5c703bf720b51138d0bfc173618807c9ee2490a7541dd3d9",
        "5bb4e7ea95dcd6a014a6fef62e62467d67d8e582326443f3d68e71d6320a9fcf",
        "5c58fe613dc5e5336357eff555824a314d8e43282600435c8d1cb6a7a2fedd13",
        "5e7cecbaadb83884793e05828cee59b210b24583b9c7425d0ba6a754fe22eb4e",
        "616f097f2fe415bc92a247f02e11f634e1f9e9a83d327e3c915c15089c87869e",
        "63bbfd5ded17c4840ac07cd8f1c21ba9d9708141f840b324f422f41b207e3973",
        "64faea20f4e2613363a1a9b9c7dd73058f3ecd00133a511e72ad7c511658f527",
        "661c298b4821edebead0c91edd2b00374d67ad7c5a1f7a91d4442633b79d6a72",
        "68e62fe11f30d5ca8289242866f0a5291402d8529ca2178ab8afc5c9694ae890",
        "6a8dddef476fab96d066d578fc88526767b836ab5ab21754e1d5bf3879c31c7c",
        "6e192623c49c94421616a5778fba35cf0d5a8d000650c1967ef4448ee5cdd990",
        "7225e4514edb64eb6740324353e0da0711954fd8d7da4576755b1c6e09b697cd",
        "75f80557d1389eddbd0de2681f6a390a0c5338c31ddaa821381c203fc3fd50d9",
        "770de9db11e84213beec501cfcaa013b019820ca881e03344dea5844f7876d94",
        "7750c6449dff7864bb9bb27ddfb0267756189201a3afc911d82b3caacd70dfc3",
        "7bde5e4cc5c10140859842b9d383af292b22639a4dffb725314baf45968cef80",
        "7ce713ace7c0e4520535b42b77eaa742c16dab813978064913e5a3cf82973b41",
        "7da0c5eff80f0197f3b3d1232ec5a682a9325f4ae9016a78f5f5ca35f9ced1f5",
        "7dbb61fe3a7699468030f71bbe5f8a0e326a151daa91beb11a6fc1f980c55e1c",
        "811bd1e21d32de12efca32393a0ab3f5133b54fce9bd44b8bd77ab07da14bf6a",
        "8ef53b2de9bcb9197d31854256575d59dbac0cba72ac627bb291ef5eceb74be4",
        "937c0052c05a31ca1daf18de3158eed4dbfcb9cc107adbea227728d647be701e",
        "9d2055050ea716bd38b7f7f1579c275386646b4894c155a3e2f3cd62ed41b7c6",
        "9f8d177621de5cb38ee3e731eda45d421db093ec0739f46a5594babda7987a98",
        "a2d7755bef5a12ed488f4ef1f1b69ee9191d7396083b755a5d2295f6edb4768b",
        "a48d62ab9d6f4f98c983223a547af44be6ca3691074c31cecced6facd3ba2dc1",
        "a4f00aa42f75d6e4595e8866e748cc1705adc0cddfeb2ca86d0d03993d63ba03",
        "a6e721d4b0e45d5b65e87534470e67b18dcd092c83f68fba09f152b9cbc061af",
        "a730a083190634c65cca36ba5f489531576ebd79bcd5c8e172130f6453127231",
        "a931079504ecc49efed7744c476a5c343a92fabf66dec2db95edb1b2fdc770e2",
        "aa9511c62d14da7aacc9b4bf51f3f697a621e83b2d6919008243c3aad168eea3",
        "ab36d55f9ed2d067327667c2fea18dda018eb628dd6347aa01dda6cf1f5d3836",
        "ad2c86c495b899d862ea0f4b42891b8713a3bd45dd4105c7fd51c2a72f39f3a5",
        "aeae0e330c9f6acd681f647d46cefd30c29f93e3392882e792e82080c9691399",
        "b0431303acaea1089ad4b3e9ce4e6518193def1118d4073ca848635ee4ea2e96",
        "b5bdfd1c873d4e093aabc0ca84c4ca6dbc4f752afb5c86f146d9742580c9da2e",
        "baed1e86cc735622097354b9d1281406caf42ff42a886d29faa8e8d1630333be",
        "c1453022f490d2459a11819d83ad1d586e9ff65a12ac3e705ffebd46d3685dcf",
        "c26608d2222fb1e94487e4a387d85f13eb55d5ed725cb25a0c589ac4ee60e7bc",
        "c7659f22557c5a0bc4855cd635f55edec690cc008a40768527762cb9fb263455",
        "c8c69575568085ba0b1b10c0249d779a214aea6f6522e949a0fc9fb0fcb449d0",
        "c8d2c9fd1f2d16f780d15127abb050d13d1a76c03a4bd87d7e4980e45e511e12",
        "ca82be1a1d406ecfe1d25dc16cb33488e5a16bf4438c9fb590484ea29d92478b",
        "cc572dace3f60ef98d7b12ff411d20f5362feb31a0439eab0085bbfd349982d7",
        "d18e5ac0f2f03f4f518d3e23db0f0cad7faa1da8620e9c09461d443bbf6e6692",
        "d28630f5854ab07ab1fd4aba756de52326c82e6be15d414b12793f1975048b54",
        "d9c275eaacd24aa73f94ffd6de08fc3f932424d8b6c376f4bed7cde376fe7bc3",
        "da0e573f9f97159390c89d9f1a9e41908b66d408cc5b58d08cf3847d844c531b",
        "dd31f52ea1086513bb9df30f8fcee9b8918323ae067a3d5b78bc826a000712be",
        "dddad92b554513a31f272570678ba307fb9f618f05e3d4a5eacafff9eae03e1d",
        "df423d40ee8654634421812bc3b196da3f9bd7d32929da813f8394c4348a5358",
        "df913725b79db7bcf03448f36b7bf8815363417d5b58deecf9305e3e30f0f21a",
        "e0bcb7e0f677f543555d2adff3bf19c05f66cdb4796e5ff602442ab2fe3c4ef7",
        "e2d65b31f36619cda3999b78b2aa9632e76b78448e7a56fc4240824200e7c4fc",
        "e6e8cff14d6fb0be70a09c0bdc58096f501952d04624ebf867e0e56da2df8960",
        "f16c709686a78c727bbbf059f92b0bf41c6fc60deec706d2dc19f529175a6125",
        "f24fb43132a4c6b4cb4eb029492919b2db645be6808d738f244fd146c03c32cb",
        "f53e442b08449d42821fa4a4fba000095af9f62742a500f978a9f557ec44339a",
        "f5cfbc5fe74540d335175b656c725d74d90e3730c626d92575eea35029d9afaa",
        "f81b3b8f3d4e343550fa4baa0e479bba9f2d29ce9c2e9b51d1ce1718d7442fcf",
        "f8ec5e643a9a937f64e1999eb9f75d072263751912dc5cd06d3c85f8f44be7c3",
        "fb92203a88b3d3053034db775110081c49d28be6551923805e039924093761e4",
        "fcd22650c908d7b7da162bbfaab594a1227a15d1643a98c68b122ac642fa2264",
    ),
    "pycparser==3.12": (  # 2 files
        "a076f3f489b39b43ed13563a1dafe42447445bec2e294154ec5c57fcdda4c85e",
        "f03387877eab82ce01bbdfd0ba7252ee55a90b1c708d5129e2ce915475cf1db6",
    ),
}


def hashed_requirements(text: str) -> tuple:
    """(lines for pip --require-hashes, pins in `text` without known hashes). No pins: ([], [])."""
    pins = [line.split("#", 1)[0].strip() for line in text.splitlines()]
    pins = [p.replace(" ", "").lower() for p in pins if p]
    unknown = [p for p in pins if p not in REQUIREMENT_HASHES]
    if not pins or unknown:
        return [], unknown
    return [f"{k} " + " ".join("--hash=sha256:" + h for h in v) for k, v in REQUIREMENT_HASHES.items()], []
