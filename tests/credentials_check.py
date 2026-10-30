"""Offline checks of the credential chain, the OS keychain store, the session cache and the
trusted-device token. subprocess, getpass and the DSM HTTP calls are all mocked."""
import json
import os
import socket
import subprocess
import sys

import _env

from nas import config
from nas.backends import PasswordBackend
from nas.credentials import Credentials, parse_op_item, parse_op_ref
from nas.errors import NasError


class Run:
    """Stands in for subprocess.run: answers by argv prefix, records every call."""

    def __init__(self, answers=None, missing=()):
        self.answers, self.missing, self.calls = dict(answers or {}), set(missing), []

    def __call__(self, argv, input=None, env=None, shell=False, **kw):
        self.calls.append({"argv": argv, "input": input, "env": env, "shell": shell})
        key = argv if isinstance(argv, str) else " ".join(argv)
        tool = key.split()[0]
        if tool in self.missing:
            raise FileNotFoundError(tool)
        for prefix, (rc, out) in self.answers.items():
            if key.startswith(prefix):
                return subprocess.CompletedProcess(argv, rc, out, "")
        return subprocess.CompletedProcess(argv, 1, "", "not found")


def creds(cfg_creds, run=None, tty=False, env=None, platform="linux", which=None, typed="typed-pw"):
    base = json.loads(json.dumps(config.DEFAULTS))
    base["credentials"].update(op_token_file=os.path.join(_env.TMP, "no-token"), store="")
    base["credentials"].update(cfg_creds)
    return Credentials(base, run=run or Run(), getpass=lambda prompt: typed, isatty=lambda: tty,
                       which=which or (lambda name: None), environ=env if env is not None else {}, platform=platform)


def expect_error(fn, *words):
    try:
        fn()
    except NasError as e:
        for w in words:
            assert w in str(e), (w, str(e))
        return str(e)
    raise AssertionError("no error")


assert parse_op_ref("op://Vault/My Item/password") == ("Vault", "My Item", "password")
assert parse_op_item("op://Vault/My Item") == ("Vault", "My Item")
expect_error(lambda: parse_op_ref("Vault/Item/x"), "op://")

# 1. op: the reference is read with `op read`; service-account token from env, token file, or neither
run = Run({"op read op://V/I/username": (0, "ops\n"), "op read op://V/I/password": (0, "s3cret\n")})
c = creds({"op_username": "op://V/I/username", "op_password": "op://V/I/password"}, run)
assert c.source() == "op" and c.username() == "ops" and c.password() == "s3cret"
assert c.describe() == {"source": "op", "op_ref": "op://V/I"}
assert run.calls[0]["env"] is None, "no token file, no env token: op uses its own sign-in"
tok = os.path.join(_env.TMP, "sa-token")
open(tok, "w").write("ops_TESTTOKEN\n")
c = creds({"op_password": "op://V/I/password", "username": "ops", "op_token_file": tok}, run)
c.password()
assert run.calls[-1]["env"]["OP_SERVICE_ACCOUNT_TOKEN"] == "ops_TESTTOKEN"
c = creds({"op_password": "op://V/I/password", "username": "ops", "op_token_file": tok}, run,
          env={"OP_SERVICE_ACCOUNT_TOKEN": "from-env"})
c.password()
assert run.calls[-1]["env"] is None, "OP_SERVICE_ACCOUNT_TOKEN already set: env passed through unchanged"
# op missing is an error only when an op reference is configured
c = creds({"op_password": "op://V/I/password", "username": "ops"}, Run(missing={"op"}))
expect_error(c.password, "`op` not found")
run = Run(missing={"op"})
c = creds({}, run, env={"NAS_USER": "ops", "NAS_PASSWORD": "pw"})
c.cfg["username"] = "ops"
assert c.source() == "env" and c.password() == "pw" and not run.calls, "op never run without an op reference"

# 2. command: NAS_PASSWORD_COMMAND beats credentials.password_command; runs through the shell
run = Run({"security find-generic-password -s nas -w": (0, "from-keychain\n"),
           "pass show nas": (0, "from-pass\nurl: https://example\n")})
c = creds({"username": "ops", "password_command": "pass show nas"}, run)
assert c.source() == "command" and c.password() == "from-pass" and run.calls[-1]["shell"] is True
c = creds({"username": "ops", "password_command": "pass show nas"}, run,
          env={"NAS_PASSWORD_COMMAND": "security find-generic-password -s nas -w"})
assert c.password() == "from-keychain"
c = creds({"username": "ops", "password_command": "false"}, Run())
expect_error(c.password, "password command failed")
assert c.writable_store() is None, "a command source cannot be updated"

# 3. keychain: macOS `security`, Linux `secret-tool`; password goes through stdin, never argv
mac = Run({"security find-generic-password -s synology-nas-cli -a ops -w": (0, "kc-pw\n"),
           "security find-generic-password -s synology-nas-cli": (0, '    "acct"<blob>="ops"\n'),
           "security -i": (0, ""), "security delete-generic-password": (0, "")})
c = creds({"store": "auto"}, mac, platform="darwin", which=lambda n: "/usr/bin/" + n)
assert c.store_kind() == "keychain" and c.source() == "keychain"
assert c.username() == "ops" and c.password("ops") == "kc-pw" and c.writable_store() == "keychain"
c.store_write("ops", 'we"ird\\pa ss')
w = mac.calls[-1]
assert w["argv"] == ["security", "-i"] and "we\\\"ird\\\\pa ss" in w["input"] and "pa ss" not in " ".join(w["argv"])
assert c.store_delete("ops") and mac.calls[-1]["argv"][:2] == ["security", "delete-generic-password"]
lin = Run({"secret-tool search service synology-nas-cli": (0, "attribute.account = ops\n"),
           "secret-tool lookup service synology-nas-cli account ops": (0, "st-pw"),
           "secret-tool store": (0, "")})
c = creds({"store": "auto"}, lin, platform="linux", which=lambda n: "/usr/bin/" + n)
assert c.store_kind() == "secret-tool" and c.source() == "keychain" and c.password("ops") == "st-pw"
c.store_write("ops", "new-pw")
assert lin.calls[-1]["input"] == "new-pw" and "new-pw" not in lin.calls[-1]["argv"]
assert creds({"store": "auto"}, Run(), platform="win32").store_kind() is None

# 4. env, 5. prompt, and nothing configured
c = creds({}, env={"NAS_USER": "ops", "NAS_PASSWORD": "env-pw"})
assert c.source() == "env" and c.password() == "env-pw"
c = creds({"username": "ops"}, tty=True, typed="typed")
assert c.source() == "prompt" and c.password("ops") == "typed" and c.password("ops") == "typed"
msg = expect_error(creds({"username": "ops"}).source, "no DSM credentials configured", "NAS_PASSWORD_COMMAND")
from nas.errors import InputRequired, can_prompt, set_no_input
try:
    creds({"username": "ops"}).source()
except InputRequired as e:
    assert e.exit_code == 3
# --no-input / NAS_NO_INPUT switch prompting off even on a terminal
set_no_input(True)
assert not can_prompt()
set_no_input(False)
os.environ["NAS_NO_INPUT"] = "1"
assert not can_prompt()
del os.environ["NAS_NO_INPUT"]
# forcing a source
c = creds({"source": "env", "op_password": "op://V/I/password"}, env={"NAS_PASSWORD": "forced"})
assert c.source() == "env" and c.password() == "forced"
expect_error(creds({"source": "magic"}).source, "credentials.source")

# 2FA code: otp_command, else op --otp when the password came from op, else a prompt
c = creds({"username": "ops", "password_command": "x", "otp_command": "oathtool --totp"},
          Run({"oathtool --totp": (0, "123456\n")}))
assert c.otp() == "123456"
run = Run({"op item get I --vault V --otp": (0, "654321\n")})
c = creds({"username": "ops", "op_password": "op://V/I/password"}, run)
assert c.otp() == "654321"
assert creds({"username": "ops", "password_command": "x"}, tty=True, typed="111222").otp() == "111222"
assert creds({"username": "ops", "password_command": "x"}).otp() is None

# writing a rotated password to 1Password goes through `op item edit` stdin
item = {"id": "abc", "fields": [{"id": "password", "label": "password", "value": "old"},
                                {"id": "username", "label": "username", "value": "ops"}]}
run = Run({"op item get I --vault V --format json": (0, json.dumps(item)), "op item edit I --vault V": (0, "{}")})
c = creds({"username": "ops", "op_password": "op://V/I/password"}, run)
assert c.writable_store() == "op"
c.write_password("ops", "N3w-Secret")
edit = run.calls[-1]
assert edit["argv"] == ["op", "item", "edit", "I", "--vault", "V"] and "N3w-Secret" not in " ".join(edit["argv"])
assert json.loads(edit["input"])["fields"][0]["value"] == "N3w-Secret"


# --- PasswordBackend: login, 2FA retry, trusted device, session cache, renewal ----------------
srv = socket.socket()
srv.bind(("127.0.0.1", 0))
srv.listen(16)
ORIGIN = f"https://127.0.0.1:{srv.getsockname()[1]}"
INFO = {"SYNO.API.Auth": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 7},
        "SYNO.Core.System": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1, "requestFormat": "JSON"}}


class FakeDSM:
    def __init__(self, need_otp=False):
        self.need_otp, self.logins, self.valid, self.calls, self.device = need_otp, [], set(), [], None

    def http(self, path, fields=None, timeout=60):
        f = dict(fields or {})
        if f.get("method") == "login":
            self.logins.append(f)
            if f["passwd"] != "pw":
                return {"success": False, "error": {"code": 400}}
            trusted = self.device and f.get("device_id") == self.device
            if self.need_otp and not trusted and f.get("otp_code") != "246810":
                return {"success": False, "error": {"code": 403}}
            sid = f"sid{len(self.logins)}"
            self.valid.add(sid)
            data = {"sid": sid, "synotoken": "tok"}
            if f.get("enable_device_token") == "yes":
                self.device = data["did"] = "DEVICE-1"
            return {"success": True, "data": data}
        if f.get("method") == "logout":
            self.valid.discard(f.get("_sid"))
            return {"success": True}
        self.calls.append(f)
        if f.get("_sid") not in self.valid:
            return {"success": False, "error": {"code": 119}}
        return {"success": True, "data": {"firmware_ver": "DSM 7.4.1-90080"}}


def backend(dsm, c, use_cache=True):
    b = PasswordBackend([ORIGIN], c, config.get(), use_cache=use_cache)
    b._http = dsm.http
    b._info = INFO
    return b


_env.use_config({"session": {"cache_file": os.path.join(_env.TMP, "s", "session.json"),
                             "device_token_file": os.path.join(_env.TMP, "s", "device.json")}})
sysinfo = [{"api": "SYNO.Core.System", "method": "info", "version": 1}]
pw = creds({"username": "ops", "password_command": "x"}, Run({"x": (0, "pw\n")}))

# default: per-command login and logout, nothing cached
dsm = FakeDSM()
b = backend(dsm, pw)
assert b.session_kind is None and b.call_many(sysinfo)[0]["ok"] and b.session_kind == "login"
b.logout()
assert not dsm.valid and not os.path.exists(config.path(config.get()["session"]["cache_file"]))

# wrong password: one attempt, no retry (AutoBlock counts every failure)
dsm = FakeDSM()
bad = creds({"username": "ops", "password_command": "x"}, Run({"x": (0, "wrong\n")}))
from nas.errors import AuthFailed, Blocked
try:
    backend(dsm, bad).call_many(sysinfo)
    raise AssertionError("wrong password accepted")
except AuthFailed as e:
    assert e.exit_code == 4 and "code 400" in str(e) and "AutoBlock" in str(e)
assert len(dsm.logins) == 1

# AutoBlock: 407 is its own exit code
blocked = FakeDSM()
blocked.http = lambda path, fields=None, timeout=60: {"success": False, "error": {"code": 407}}
try:
    backend(blocked, pw).call_many(sysinfo)
    raise AssertionError("blocked login accepted")
except Blocked as e:
    assert e.exit_code == 5 and "AutoBlock" in str(e)

# 2FA: 403 -> one retry with the code; --trust-device stores DSM's device id and later logins send it
dsm = FakeDSM(need_otp=True)
otp = creds({"username": "ops", "password_command": "x", "otp_command": "o"},
            Run({"x": (0, "pw\n"), "o": (0, "246810\n")}))
b = backend(dsm, otp, use_cache=False)
b.trust_device = True
b.login(save=True)
assert [x.get("otp_code") for x in dsm.logins] == [None, "246810"] and dsm.logins[1]["enable_device_token"] == "yes"
dev = json.load(open(config.path(config.get()["session"]["device_token_file"])))
assert dev == {"devices": {"ops": "DEVICE-1"}}
cache = config.path(config.get()["session"]["cache_file"])
assert oct(os.stat(cache).st_mode & 0o777) == "0o600" and json.load(open(cache))["sid"] == "sid2"
n = len(dsm.logins)
b2 = backend(dsm, otp, use_cache=False)
b2.login()
assert len(dsm.logins) == n + 1 and dsm.logins[-1]["device_id"] == "DEVICE-1" and "otp_code" not in dsm.logins[-1]

# cached session (`nas login`): reused without a login, never logged out by a command, renewed on 119
b3 = backend(dsm, otp)
assert b3.session_kind == "cache" and b3.call_many(sysinfo)[0]["ok"]
n = len(dsm.logins)
b3.logout()
assert "sid2" in dsm.valid and len(dsm.logins) == n, "a command does not end the cached session"
dsm.valid.clear()  # DSM expired it
b4 = backend(dsm, otp)
assert b4.call_many(sysinfo)[0]["ok"] and len(dsm.logins) == n + 1
assert json.load(open(cache))["sid"] == b4._sid != "sid2", "renewed session written back"
b4.logout(force=True)
assert b4.drop_session() and not os.path.exists(cache)

# pasted session: NAS_SID + NAS_SYNOTOKEN, no login; rejected -> clear error, no login attempt
dsm = FakeDSM()
dsm.valid.add("pasted")
os.environ.update(NAS_SID="pasted", NAS_SYNOTOKEN="tok")
b5 = backend(dsm, pw)
assert b5.session_kind == "env" and b5.call_many(sysinfo)[0]["ok"] and not dsm.logins
dsm.valid.clear()
expect_error(lambda: backend(dsm, pw).call_many(sysinfo), "NAS_SID", "rejected")
assert not dsm.logins
del os.environ["NAS_SID"], os.environ["NAS_SYNOTOKEN"]
srv.close()
print(f"credential checks ok (python {sys.version.split()[0]})")
