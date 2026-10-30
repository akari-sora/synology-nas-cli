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
print(json.dumps({"complete": True, "regions": 1, "selected_mappings_complete": True, "excluded_unaddressable": 0,
                  "receipt": os.path.join(a.output, "capture.json")}))
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
             yes=True, force=False)
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

# CLI parsing
from nas import cli
a = cli.parse_args(["incident", "rescue", "--capture-dir", "/usbshare1/r", "--sample", "/docs/x.L0CK3D",
                    "--decrypt-from", "/docs", "--decrypt-to", "/mnt/out", "--pid", "5", "--yes", "--keep-on-nas"])
assert a.action == "rescue" and a.capture_dir == "/usbshare1/r" and a.pid == [5] and a.yes and a.keep_on_nas
print(f"rescue checks ok (python {sys.version.split()[0]})")
