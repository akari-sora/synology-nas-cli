"""Offline checks of `nas incident rescue`: a fake c3rb3r-rescue checkout (stub scripts written for these tests
that accept the toolkit's command lines), a fake NAS tree and /proc, the local root runner. Covers the whole
flow (contain -> toolkit pin check -> capture -> pull -> venv -> keys -> sample -> batch decrypt), resume,
the same-volume refusal and its --force, --keep-on-nas, no input without --yes, and the JSON schema."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import types

import _env

from nas import rescue
from nas.errors import InputRequired
from jsonschema_min import validate

T = os.path.join(_env.TMP, "rescue")
R = os.path.join(T, "nasroot")
EXE = b"ELF-libgld-sample"
KEY = b"K" * 48
SCHEMA = json.load(open(os.path.join(_env.ROOT, "schemas", "incident-rescue.schema.json")))


def write(path, data, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb" if isinstance(data, bytes) else "w") as f:
        f.write(data)
    os.chmod(path, mode)


def encrypt(plain: bytes, marker="ce35a593") -> bytes:  # the stubs' toy format: reversed bytes + marker footer
    return b"CIPHER:" + plain[::-1] + b"|MARKER=" + marker.encode()


# --- a fake toolkit checkout: same paths and command lines, stub behaviour ----------------------------------
TK = os.path.join(T, "toolkit-src")
S = os.path.join(TK, "skills/dsm-ransomware-rescue/scripts")
write(os.path.join(TK, "requirements.txt"), "# pinned requirements of the toolkit (none for the stubs)\n")
write(os.path.join(TK, "tests/test_stub.py"), "import unittest\nclass T(unittest.TestCase):\n    def test_ok(self):\n        pass\n")
write(os.path.join(TK, "skills/dsm-ransomware-rescue/assets/libgld-802ac85d.json"),
      json.dumps({"packed_sha256": hashlib.sha256(EXE).hexdigest(), "unpacked_sha256": "0" * 64}))
write(os.path.join(S, "capture_process_memory.py"), r'''
import argparse, hashlib, json, os, sys
p = argparse.ArgumentParser(); sub = p.add_subparsers(dest="action", required=True)
i = sub.add_parser("inspect"); i.add_argument("--pid", type=int, required=True)
c = sub.add_parser("capture"); c.add_argument("--pid", type=int, required=True)
c.add_argument("--expected-start-ticks", type=int, required=True); c.add_argument("--expected-exe-sha256", required=True)
c.add_argument("--expected-output-device", type=int, required=True); c.add_argument("--output", required=True)
a = p.parse_args()
EXE = b"ELF-libgld-sample"
if a.action == "inspect":
    print(json.dumps({"state": "T", "start_ticks": 4242, "threads": {str(a.pid): {"state": "T", "tracer_pid": 0}},
                      "pid": a.pid, "exe_sha256": hashlib.sha256(EXE).hexdigest(), "readable_bytes": 8192,
                      "excluded_unaddressable": []})); sys.exit(0)
if a.expected_start_ticks != 4242 or os.stat(os.path.dirname(a.output)).st_dev != a.expected_output_device:
    print("identity/device check failed", file=sys.stderr); sys.exit(1)
os.mkdir(a.output, 0o700)
region = b"\x00" * 4096
open(os.path.join(a.output, "map-1000-2000.bin"), "wb").write(region)
open(os.path.join(a.output, "executable.bin"), "wb").write(EXE)
open(os.path.join(a.output, "maps.snapshot"), "w").write("1000-2000 rw-p 0 00:00 0\n")
json.dump({"schema": 1, "format": "linux-process-mappings", "exe_sha256": a.expected_exe_sha256, "complete": True,
           "regions": [{"start": 4096, "end": 8192, "file": "map-1000-2000.bin",
                        "sha256": hashlib.sha256(region).hexdigest(), "holes": []}]},
          open(os.path.join(a.output, "capture.json"), "w"))
link = os.environ.get("STUB_LINK_TARGET")  # links the chown walk must leave alone
if link:
    os.symlink(link, os.path.join(a.output, "link-dir"))
    os.symlink(os.path.join(link, "f"), os.path.join(a.output, "link-file"))
print(json.dumps({"complete": True, "regions": 1, "selected_mappings_complete": True, "excluded_unaddressable": 0,
                  "receipt": os.path.join(a.output, "capture.json"), "argv0": sys.argv[0]}))
''')
write(os.path.join(S, "recover_process_key.py"), r'''
import argparse, json, os, sys
p = argparse.ArgumentParser(); p.add_argument("--capture", required=True); p.add_argument("--profile", required=True)
p.add_argument("--output", required=True); a = p.parse_args()
m = json.load(open(os.path.join(a.capture, "capture.json"))); prof = json.load(open(a.profile))
if m["exe_sha256"] not in (prof["packed_sha256"], prof["unpacked_sha256"]):
    raise ValueError("Executable does not match the reviewed sample profile")
os.umask(0o077); os.mkdir(a.output, 0o700)
fd = os.open(os.path.join(a.output, "master-candidate.bin"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.write(fd, b"K" * 48); os.close(fd); os.chmod(os.path.join(a.output, "master-candidate.bin"), 0o400)
r = {"candidate_file": "master-candidate.bin", "bytes": 48, "capture_complete": m["complete"],
     "validation": "structural candidate only; full-file cryptographic comparison required"}
json.dump(r, open(os.path.join(a.output, "candidate.json"), "w")); print(json.dumps(r))
''')
write(os.path.join(S, "inspect_footer.py"), r'''
import argparse, json, sys
p = argparse.ArgumentParser(); p.add_argument("--input-copy", required=True); a = p.parse_args()
data = open(a.input_copy, "rb").read()
if b"|MARKER=" not in data:
    print("Inspection refused: no footer", file=sys.stderr); sys.exit(1)
print(json.dumps({"schema": 1, "marker": data.rsplit(b"|MARKER=", 1)[1].decode(), "original_size": len(data)}))
''')
write(os.path.join(S, "decrypt_copy.py"), r'''
import argparse, hashlib, json, os, sys
p = argparse.ArgumentParser()
for n in ("--copy-root", "--input-copy", "--master-file", "--output"):
    p.add_argument(n, required=True)
p.add_argument("--expected-sha256"); p.add_argument("--expected-marker", default="ce35a593"); a = p.parse_args()
if not os.path.realpath(a.input_copy).startswith(os.path.realpath(a.copy_root) + os.sep):
    print("Recovery refused/failed: input outside copy root", file=sys.stderr); sys.exit(1)
if os.path.exists(a.output):
    print("Recovery refused/failed: output exists", file=sys.stderr); sys.exit(1)
data = open(a.input_copy, "rb").read(); body, marker = data.rsplit(b"|MARKER=", 1)
if marker.decode() != a.expected_marker:
    print("Recovery refused/failed: marker differs", file=sys.stderr); sys.exit(1)
if open(a.master_file, "rb").read() != b"K" * 48:
    print("Recovery refused/failed: AES record check failed", file=sys.stderr); sys.exit(1)
plain = body[len(b"CIPHER:"):][::-1]; h = hashlib.sha256(plain).hexdigest()
if a.expected_sha256 and h != a.expected_sha256:
    print("Recovery refused/failed: Recovered file does not match the expected SHA-256", file=sys.stderr); sys.exit(1)
fd = os.open(a.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); os.write(fd, plain); os.close(fd)
print(json.dumps({"output": a.output, "bytes": len(plain), "sha256": h, "observed_marker": marker.decode(),
                  "verification": "known-original-sha256" if a.expected_sha256 else "key-record-only"}))
''')
write(os.path.join(S, "verify_backup.py"), "import sys\nprint('self-test passed')\nsys.exit(0)\n")
git = lambda *a: subprocess.run(["git", "-C", TK] + list(a), capture_output=True, text=True, check=True).stdout.strip()
git("init", "-q")
git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "add", "-A")
git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "stub toolkit")
PIN = git("rev-parse", "HEAD")

# --- a fake NAS: shares, encrypted files, /proc with a stopped libgld -------------------------------------------
PLAIN_A, PLAIN_B = b"quarterly report contents", b"photo bytes " * 50
write(R + "/volume1/docs/a.txt.L0CK3D", encrypt(PLAIN_A))
write(R + "/volume1/docs/sub/b.jpg.L0CK3D", encrypt(PLAIN_B))
write(R + "/volume1/docs/read-me3.txt", "C3RB3R INSTRUCTIONS")
os.makedirs(R + "/volumeUSB1/usbshare", exist_ok=True)
os.makedirs(R + "/root", exist_ok=True)
write(R + "/proc/uptime", "10000.00 9000.00\n")
d = R + "/proc/202"
os.makedirs(d + "/fd", exist_ok=True)
os.makedirs(d + "/task/202", exist_ok=True)
os.symlink("/bin/libgld", d + "/exe")
os.symlink("/volume1/docs/sub/b.jpg.L0CK3D", d + "/fd/3")
stat = "202 (libgld) T " + " ".join(["0"] * 51)
for p, c in (("comm", "libgld\n"), ("cmdline", "/bin/libgld"), ("stat", stat), ("status", "Threads:\t1\n"),
             ("cgroup", ""), ("task/202/stat", stat)):
    write(d + "/" + p, c)
SIGLOG = os.path.join(T, "signals.log")
EXTRA = {"signal_log": SIGLOG, "clk_tck": 100}


class Sess:
    backend_name = "password"

    def call(self, api, method, params=None, version=None, timeout=None):
        if (api, method) == ("SYNO.FileStation.List", "list_share"):
            return {"ok": True, "data": {"shares": [
                {"name": "docs", "additional": {"real_path": R + "/volume1/docs"}},
                {"name": "usbshare1", "additional": {"real_path": R + "/volumeUSB1/usbshare"}}]}}
        if (api, method) == ("SYNO.Core.Package", "list"):
            return {"ok": True, "data": {"packages": []}}
        return {"ok": False, "error": {"code": 102}}


def cfg(**inc):
    base = {"rescue_repo": TK, "rescue_commit": PIN, "rescue_min_python": "%d.%d" % sys.version_info[:2]}
    base.update(inc)
    _env.use_config({"incident": base, "session": {"cache_file": os.path.join(T, "c", "s.json")}})


def args(**kw):
    a = dict(workdir=os.path.join(T, "work"), no_contain=False, rescue_dir=None, capture_dir="/usbshare1/rescue",
             keep_on_nas=False, sample=None, expected_sha256=None, expected_marker=None, decrypt_from=None,
             decrypt_to=None, keep_copies=False, python=sys.executable, pid=None, stop_sync=False, cpu_threshold=50.0,
             yes=True, force=False, force_same_volume=False, force_unverified_key=False, force_unpinned_toolkit=False)
    a.update(kw)
    return types.SimpleNamespace(**a)


def run(**kw):
    lines, data, rc = rescue.rescue(Sess(), args(**kw), root=R, extra=EXTRA)
    errs = validate(json.loads(json.dumps(data)), SCHEMA, SCHEMA)
    assert not errs, errs[:3]
    return lines, data, rc


cfg()
# no --yes, no terminal: the plan and exit 3; nothing frozen
lines, data, rc = run(yes=False, workdir=os.path.join(T, "w0"))
assert rc == 3 and lines[-1] == "Not applied: add --yes (or NAS_YES=1)." and not os.path.exists(SIGLOG), lines
assert any("capture: process memory to /usbshare1/rescue" in l for l in data["plan"])
try:
    rescue.rescue(Sess(), args(capture_dir=None, workdir=os.path.join(T, "w1")), root=R, extra=EXTRA)
    raise AssertionError("missing --capture-dir accepted")
except InputRequired as e:
    assert "--capture-dir" in str(e)

# the pinned commit is checked after the clone
cfg(rescue_commit="1" * 40)
lines, data, rc = run(workdir=os.path.join(T, "w2"), no_contain=True, pid=[202])
assert rc == 1 and data["failed_step"] == "toolkit" and data["steps"]["toolkit"]["status"] == "failed", data
cfg()

# the capture folder sits on the same filesystem as the encrypted share here: refused, override named
lines, data, rc = run()
assert rc == 1 and data["failed_step"] == "capture" and "override: --force" in data["steps"]["capture"]["message"]
assert data["steps"]["contain"]["frozen"] == [202] and "202 SIGSTOP" in open(SIGLOG).read()
assert data["steps"]["toolkit"]["commit"] == PIN and data["steps"]["toolkit"]["commit_matches"]
assert "USB disk" in data["next_steps"][0]
assert not os.listdir(R + "/volumeUSB1/usbshare/rescue"), "no case folder written when refused"

# same workdir, --force and the full flow: earlier steps are resumed, not repeated
sha_a = hashlib.sha256(PLAIN_A).hexdigest()
out_dir = os.path.join(T, "decrypted")
lines, data, rc = run(force=True, sample="/docs/a.txt.L0CK3D", expected_sha256=sha_a, decrypt_from="/docs",
                      decrypt_to=out_dir)
st = data["steps"]
assert rc == 0 and data["failed_step"] is None, (lines, data)
assert open(SIGLOG).read().count("SIGSTOP") == 1, "contain was resumed, not run again"
assert "contain: done earlier (resumed)" in lines and "toolkit: done earlier (resumed)" in lines
cap = st["capture"]["captures"][0]
assert cap["exit"] == 0 and cap["reviewed_sha256_match"] and cap["inspect"]["threads"] == {"202": "T"}
assert os.path.isdir(R + "/volumeUSB1/usbshare/rescue/" + st["capture"]["case"] + "/pid-202")
assert not os.path.exists(R + "/volumeUSB1/usbshare/rescue/" + st["capture"]["case"] + "/.capture_process_memory.py")
assert st["pull"]["pulled"][0]["checksum_mismatch"] == [] and st["venv"]["self_tests_ok"]
cand = st["keys"]["candidates"][0]["file"]
assert oct(os.stat(cand).st_mode & 0o777) == "0o400" and oct(os.stat(os.path.dirname(cand)).st_mode & 0o777) == "0o700"
assert KEY.decode() not in json.dumps(data) and KEY.decode() not in "\n".join(lines), "key bytes never printed"
assert st["sample"]["verified_pid"] == 202 and st["sample"]["verification"] == "known-original-sha256"
assert st["decrypt"]["counts"] == {"decrypted": 2, "skipped_existing": 0, "failed": 0, "not_encrypted": 1}, st["decrypt"]
assert open(os.path.join(out_dir, "a.txt"), "rb").read() == PLAIN_A
assert open(os.path.join(out_dir, "sub", "b.jpg"), "rb").read() == PLAIN_B
assert sorted(os.listdir(R + "/volume1/docs")) == ["a.txt.L0CK3D", "read-me3.txt", "sub"], "nothing written to the NAS share"
assert not os.listdir(os.path.join(T, "work", "copies", "batch", "sub")), "ciphertext copies removed after success"

# running again: everything resumed, decrypted files kept
lines, data, rc = run(force=True, sample="/docs/a.txt.L0CK3D", expected_sha256=sha_a, decrypt_from="/docs",
                      decrypt_to=out_dir)
assert rc == 0 and data["steps"]["decrypt"]["counts"]["skipped_existing"] == 2, data["steps"]["decrypt"]
assert open(SIGLOG).read().count("SIGSTOP") == 1

# a wrong expected hash: no candidate verified, batch decrypt waits for --force
lines, data, rc = run(workdir=os.path.join(T, "w3"), no_contain=True, pid=[202], force=True,
                      sample="/docs/a.txt.L0CK3D", expected_sha256="0" * 64)
assert rc == 1 and data["failed_step"] == "sample" and "no candidate decrypted" in data["steps"]["sample"]["message"]

# --keep-on-nas: capture only; the reviewed hash compared; a toolkit given with --rescue-dir
write(os.path.join(T, "other-profile.json"), "{}")
lines, data, rc = run(workdir=os.path.join(T, "w4"), no_contain=True, pid=[202], force=True, keep_on_nas=True,
                      rescue_dir=TK)
assert rc == 0 and set(data["steps"]) == {"toolkit", "capture"} and "copy it to a clean analysis machine" in data["next_steps"][0]

# --- --rescue-dir: the pinned commit and a clean checkout, or --force-unpinned-toolkit ------------------------
TK2 = os.path.join(T, "toolkit-dirty")
shutil.copytree(TK, TK2)
write(os.path.join(TK2, S[len(TK) + 1:], "json.py"), "print('shadowing module')\n")
lines, data, rc = run(workdir=os.path.join(T, "w5"), no_contain=True, pid=[202], keep_on_nas=True, rescue_dir=TK2)
tk = data["steps"]["toolkit"]
assert rc == 1 and tk["status"] == "failed" and "json.py" in tk["message"] and "--force-unpinned-toolkit" in tk["message"]
cfg(rescue_commit="2" * 40)
lines, data, rc = run(workdir=os.path.join(T, "w6"), no_contain=True, pid=[202], keep_on_nas=True, rescue_dir=TK)
assert rc == 1 and "the pinned commit is " + "2" * 40 in data["steps"]["toolkit"]["message"], data["steps"]["toolkit"]
lines, data, rc = run(workdir=os.path.join(T, "w6"), no_contain=True, pid=[202], keep_on_nas=True, rescue_dir=TK,
                      force_unpinned_toolkit=True, force_same_volume=True)
assert rc == 0 and data["steps"]["toolkit"]["unpinned_override"] and not data["steps"]["toolkit"]["commit_matches"]
cfg()

# --- requirements: pip --require-hashes with the hashes kept in rescue.REQUIREMENT_HASHES --------------------
hl, unknown = rescue.hashed_requirements("# comment\nnumpy==2.3.5\ncryptography==50.0.2\n")
assert not unknown and [l.split()[0] for l in hl] == ["numpy==2.3.5", "cryptography==50.0.2", "cffi==2.1.1",
                                                      "pycparser==3.12"], hl
assert all(len(h) == 64 for l in hl for h in (x[len("--hash=sha256:"):] for x in l.split()[1:]))
assert rescue.hashed_requirements("# none\n") == ([], [])
assert rescue.hashed_requirements("numpy==9.9.9\n")[1] == ["numpy==9.9.9"]
assert rescue.REQUIREMENTS_FOR == rescue.config.DEFAULTS["incident"]["rescue_commit"]
TK3 = os.path.join(T, "toolkit-newpins")
shutil.copytree(TK, TK3)
write(os.path.join(TK3, "requirements.txt"), "numpy==9.9.9\n")
git3 = lambda *a: subprocess.run(["git", "-C", TK3] + list(a), capture_output=True, text=True, check=True).stdout.strip()
git3("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-am", "new pins")
cfg(rescue_commit=git3("rev-parse", "HEAD"))
lines, data, rc = run(workdir=os.path.join(T, "w7"), no_contain=True, pid=[202], force_same_volume=True, rescue_dir=TK3)
v = data["steps"]["venv"]
assert rc == 1 and data["failed_step"] == "venv" and v["unknown_pins"] == ["numpy==9.9.9"], v
assert "--force-unpinned-toolkit" in v["message"] and not os.path.exists(os.path.join(T, "w7", "requirements-hashed.txt"))
cfg()

# a process that is not the reviewed encryptor: the key search reports the toolkit's exception line
TK4 = os.path.join(T, "toolkit-otherprofile")
shutil.copytree(TK, TK4)
write(os.path.join(TK4, "skills/dsm-ransomware-rescue/assets/libgld-802ac85d.json"),
      json.dumps({"packed_sha256": "1" * 64, "unpacked_sha256": "2" * 64}))
git4 = lambda *a: subprocess.run(["git", "-C", TK4] + list(a), capture_output=True, text=True, check=True).stdout.strip()
git4("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-am", "other profile")
cfg(rescue_commit=git4("rev-parse", "HEAD"))
lines, data, rc = run(workdir=os.path.join(T, "w7b"), no_contain=True, pid=[202], force_same_volume=True, rescue_dir=TK4)
k = data["steps"]["keys"]
assert rc == 1 and k["candidates"][0]["error"] == "ValueError: Executable does not match the reviewed sample profile", k
cfg()

# --- pull: free space in the workdir is checked first -------------------------------------------------------
real_usage = rescue.shutil.disk_usage
rescue.shutil.disk_usage = lambda p: types.SimpleNamespace(total=1 << 30, used=1 << 30, free=1024)
lines, data, rc = run(workdir=os.path.join(T, "w8"), no_contain=True, pid=[202], force_same_volume=True)
rescue.shutil.disk_usage = real_usage
pl = data["steps"]["pull"]
assert rc == 1 and pl["need_bytes"] == 8192 and "--workdir NEW_PATH" in pl["message"] and "--keep-on-nas" in pl["message"]
assert not os.path.exists(os.path.join(T, "w8", "captures")), "nothing pulled"

# --- a capture folder that cannot be created: the root script still writes its result -----------------------
write(R + "/volumeUSB1/usbshare/notadir", "x")
lines, data, rc = run(workdir=os.path.join(T, "w9"), no_contain=True, pid=[202], keep_on_nas=True,
                      capture_dir="/usbshare1/notadir/rescue")
c = data["steps"]["capture"]
assert rc == 1 and c["status"] == "failed" and any("notadir" in e for e in c["errors"]), c

# --- mount sources (/proc/self/mountinfo), Btrfs-shaped: subvolumes share the volume's source --------------
os.makedirs(R + "/proc/self", exist_ok=True)
write(R + "/proc/self/mountinfo",
      "20 1 9:0 / / rw,relatime - ext4 /dev/md0 rw\n"
      "30 20 0:25 /@syno /volume1 rw,relatime shared:1 - btrfs /dev/mapper/cachedev_0 rw,space_cache=v2\n"
      "31 30 0:43 /@syno/@docker /volume1/@docker rw,relatime shared:2 - btrfs /dev/mapper/cachedev_0 rw\n"
      "40 20 65:1 / /volumeUSB1/usbshare rw,relatime shared:3 - ext4 /dev/sdq1 rw\n")
os.makedirs(R + "/volume1/@docker/data", exist_ok=True)
SHARES = {"dockerdata": R + "/volume1/@docker/data", "linked": R + "/volume1/linkshare"}
os.symlink(R + "/volumeUSB1/usbshare", R + "/volume1/linkshare")


class Sess2(Sess):  # more shares; signed in as the account running the tests (the case folder is handed to it)
    backend = types.SimpleNamespace(account=__import__("getpass").getuser())

    def call(self, api, method, params=None, version=None, timeout=None):
        r = Sess.call(self, api, method, params, version, timeout)
        if (api, method) == ("SYNO.FileStation.List", "list_share"):
            r["data"]["shares"] += [{"name": n, "additional": {"real_path": p}} for n, p in SHARES.items()]
        return r


def run2(**kw):
    lines, data, rc = rescue.rescue(Sess2(), args(**kw), root=R, extra=EXTRA)
    assert not validate(json.loads(json.dumps(data)), SCHEMA, SCHEMA)
    return lines, data, rc


# USB disk: another mount source, so no override is needed (st_dev is the same here: one temp filesystem).
# The capture leaves symlinks to a folder outside the case: the chown/chmod walk does not follow them.
OUT = os.path.join(T, "outside")
write(os.path.join(OUT, "f"), "outside", mode=0o200)
os.chmod(OUT, 0o500)
os.environ["STUB_LINK_TARGET"] = OUT
lines, data, rc = run2(workdir=os.path.join(T, "w10"), no_contain=True, pid=[202], keep_on_nas=True)
del os.environ["STUB_LINK_TARGET"]
c = data["steps"]["capture"]
assert rc == 0 and c["status"] == "done" and not c["same_volume"] and c["capture_source"] == "/dev/sdq1", c
assert c["captures"][0]["summary"]["argv0"] == "-", "the verified tool runs from stdin"
case_dir = R + "/volumeUSB1/usbshare/rescue/" + c["case"]
assert c["owner"]["name"] == Sess2.backend.account and c["owner"]["uid"] == os.getuid(), c["owner"]
assert sorted(os.path.basename(x) for x in c["owner"]["skipped"]) == ["link-dir", "link-file"], c["owner"]
assert oct(os.stat(OUT).st_mode & 0o777) == "0o500" and oct(os.stat(os.path.join(OUT, "f")).st_mode & 0o777) == "0o200"
assert os.stat(case_dir).st_uid == os.getuid() and os.stat(case_dir).st_mode & 0o700 == 0o700
assert not [n for n in os.listdir(case_dir) if n.endswith(".py")], "no copy of the tool in the case folder"
os.chmod(OUT, 0o700)
# a shared folder on volume 1 and a separately mounted subvolume: both the volume's source
for share in ("/docs/rescue", "/dockerdata/rescue"):
    lines, data, rc = run2(workdir=os.path.join(T, "w11" + share.replace("/", "-")), no_contain=True, pid=[202],
                           keep_on_nas=True, capture_dir=share)
    c = data["steps"]["capture"]
    assert rc == 1 and c["same_volume"] == "/volume1" and c["capture_source"] == "/dev/mapper/cachedev_0", c
    assert "--force-same-volume" in c["message"]
# a capture folder reached through a symlink
lines, data, rc = run2(workdir=os.path.join(T, "w12"), no_contain=True, pid=[202], keep_on_nas=True,
                       capture_dir="/linked/rescue")
c = data["steps"]["capture"]
assert rc == 1 and any("symlink" in e for e in c["errors"]), c
# the local walk leaves symlinks out
os.symlink("/etc/hosts", case_dir + "/pid-202/link-out")
assert all(not rel.endswith("link-out") for rel, _f, _r in rescue.NasFiles(Sess(), R).walk(case_dir + "/pid-202", "/x"))

# the tool staged as a file (how --backend password passes it, task scripts being short): used when its
# sha256 matches the uploaded bytes, removed either way
tool_bytes = open(os.path.join(S, "capture_process_memory.py"), "rb").read()
staged = R + "/volume1/docker/.stage/nas-rescue-tool-1.py"
base = {"root": R, "capture_dir": R + "/volumeUSB1/usbshare/rescue", "pids": [202], "force": False, "owner": None,
        "affected_paths": [], "timeout": 60, "inspect_timeout": 60, "tool_path": staged,
        "tool_sha256": hashlib.sha256(tool_bytes).hexdigest()}
write(staged, tool_bytes)
d = rescue.run_root_python(Sess(), rescue.CAPTURE, dict(base, case="case-staged-ok"), "t", "capture script", root=R)
assert d["captures"][0]["exit"] == 0 and not d["errors"] and not os.path.exists(staged), d
write(staged, tool_bytes + b"# changed after the upload\n")
d = rescue.run_root_python(Sess(), rescue.CAPTURE, dict(base, case="case-staged-bad"), "t", "capture script", root=R)
assert any("sha256 differs" in e for e in d["errors"]) and not d["captures"] and not os.path.exists(staged), d

# CLI parsing
from nas import cli
a = cli.parse_args(["incident", "rescue", "--capture-dir", "/usbshare1/r", "--sample", "/docs/x.L0CK3D",
                    "--decrypt-from", "/docs", "--decrypt-to", "/mnt/out", "--pid", "5", "--yes", "--keep-on-nas"])
assert a.action == "rescue" and a.capture_dir == "/usbshare1/r" and a.pid == [5] and a.yes and a.keep_on_nas
a = cli.parse_args(["incident", "rescue", "--force-same-volume", "--force-unverified-key", "--force-unpinned-toolkit"])
assert a.force_same_volume and a.force_unverified_key and a.force_unpinned_toolkit and not a.force
assert all(rescue.forced(cli.parse_args(["incident", "rescue", "--force"]), f)
           for f in ("force_same_volume", "force_unverified_key", "force_unpinned_toolkit"))
print(f"rescue checks ok (python {sys.version.split()[0]})")
