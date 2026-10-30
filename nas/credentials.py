"""Where the DSM username, password and 2FA code come from.

Password chain ("auto"; the first source that is configured wins):

1. op       - 1Password CLI reference credentials.op_password ("op://VAULT/ITEM/FIELD").
              `op` authenticates with OP_SERVICE_ACCOUNT_TOKEN, else the token in
              credentials.op_token_file (if that file exists), else its own sign-in
              (desktop-app integration / `op signin`).
2. command  - NAS_PASSWORD_COMMAND or credentials.password_command: prints the password.
3. keychain - the entry `nas login --save` wrote: macOS Keychain (`security`) or the
              Linux Secret Service (`secret-tool`).
4. env      - NAS_PASSWORD (least safe: visible to anything that can read the environment).
5. prompt   - getpass, only when stdin is a terminal.

credentials.source (or NAS_CREDENTIAL_SOURCE) forces one of these names instead.
`op` is only ever run when an op reference is configured.

2FA code (asked for after DSM answers 403): credentials.otp_command / NAS_OTP_COMMAND,
else `op item get --otp` when the password came from 1Password, else a prompt.

Secrets are returned to the caller and never printed or written anywhere except
the store the user chose (`nas login --save`, `incident fix --rotate-password`).
"""

from __future__ import annotations

import getpass as _getpass
import json
import os
import re
import shutil
import subprocess
import sys

from . import config
from .errors import InputRequired, NasError, can_prompt

SOURCES = ("op", "command", "keychain", "env", "prompt")


def parse_op_ref(ref: str) -> tuple:
    """'op://VAULT/ITEM/FIELD' -> (vault, item, field). ITEM may contain spaces."""
    if not ref.startswith("op://"):
        raise NasError(f"{ref!r} is not a 1Password reference (op://VAULT/ITEM/FIELD)")
    parts = ref[len("op://"):].split("/")
    if len(parts) < 3 or not all(parts):
        raise NasError(f"{ref!r}: expected op://VAULT/ITEM/FIELD")
    return parts[0], "/".join(parts[1:-1]), parts[-1]


def parse_op_item(ref: str) -> tuple:
    """'op://VAULT/ITEM' -> (vault, item)."""
    if not ref.startswith("op://") or "/" not in ref[len("op://"):]:
        raise NasError(f"{ref!r}: expected op://VAULT/ITEM")
    vault, item = ref[len("op://"):].split("/", 1)
    if not vault or not item:
        raise NasError(f"{ref!r}: expected op://VAULT/ITEM")
    return vault, item.rstrip("/")


def _quote_security(value: str) -> str:
    """Quote one argument for `security -i` (reads commands from stdin, so nothing lands on argv)."""
    if "\n" in value or "\r" in value:
        raise NasError("values with line breaks cannot be stored in the Keychain by this CLI")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


class Credentials:
    def __init__(self, cfg: dict | None = None, *, run=None, getpass=None, isatty=None, which=None,
                 environ=None, platform: str | None = None):
        self.cfg = (cfg or config.get())["credentials"]
        self.run = run or subprocess.run
        self.getpass = getpass or _getpass.getpass
        self.isatty = isatty or can_prompt
        self.which = which or shutil.which
        self.environ = os.environ if environ is None else environ
        self.platform = platform or sys.platform
        self._password = None  # set by a prompt or a rotation, kept for this process only
        self.otp_once = None  # a 2FA code handed over for one login (nas setup --otp-code)
        self._source = None
        self._store_user = None

    # --- 1Password ----------------------------------------------------------

    def op_env(self) -> dict | None:
        if self.environ.get("OP_SERVICE_ACCOUNT_TOKEN"):
            return None
        path = config.path(self.cfg.get("op_token_file") or "")
        if path and os.path.isfile(path):
            if os.name == "posix" and os.stat(path).st_mode & 0o077:
                print(f"nas: warning: {path} (1Password service-account token) is readable by other users; "
                      f"chmod 600 {path}", file=sys.stderr)
            with open(path, encoding="utf-8") as f:
                return {**self.environ, "OP_SERVICE_ACCOUNT_TOKEN": f.read().strip()}
        return None  # `op` uses its own sign-in (desktop app integration or `op signin`)

    def _op(self, args: list, input_text: str | None = None, what: str = "op"):
        try:
            return self.run(["op"] + args, input=input_text, capture_output=True, text=True, timeout=60,
                            env=self.op_env())
        except FileNotFoundError:
            raise NasError("1Password CLI `op` not found, but an op:// reference is configured "
                           "(install it from 1Password, or use another credential source)")
        except subprocess.TimeoutExpired:
            raise NasError(f"{what}: `op` did not answer within 60 s (waiting for a desktop-app approval?)")

    def op_read(self, ref: str) -> str:
        parse_op_ref(ref)
        p = self._op(["read", ref], what=ref)
        if p.returncode != 0:
            first = (p.stderr.strip().splitlines() or ["unknown error"])[0]
            raise NasError(f"cannot read {ref}: {first}\n`op` needs OP_SERVICE_ACCOUNT_TOKEN, the token file "
                           f"{self.cfg.get('op_token_file')}, or a signed-in 1Password app. Item names with "
                           "non-ASCII characters fail in `op read`; use the item ID.")
        return p.stdout.rstrip("\r\n")

    def op_item_json(self, vault: str, item: str) -> dict:
        p = self._op(["item", "get", item, "--vault", vault, "--format", "json"], what=f"op://{vault}/{item}")
        if p.returncode != 0:
            first = (p.stderr.strip().splitlines() or ["unknown error"])[0]
            raise NasError(f"cannot read 1Password item {item!r} in vault {vault!r}: {first}")
        return json.loads(p.stdout)

    def op_otp(self, vault: str, item: str) -> str | None:
        try:
            p = self._op(["item", "get", item, "--vault", vault, "--otp"], what="op --otp")
        except NasError:
            return None
        code = (p.stdout or "").strip()
        return code if p.returncode == 0 and code.isdigit() else None

    def op_write(self, ref: str, value: str) -> None:
        """Set one field of an item. The JSON goes through stdin (`op item edit` piped input)."""
        vault, item, field = parse_op_ref(ref)
        doc = self.op_item_json(vault, item)
        hit = [f for f in doc.get("fields") or [] if field in (f.get("id"), f.get("label"))]
        if not hit:
            raise NasError(f"1Password item {item!r} has no field {field!r}")
        for f in hit:
            f["value"] = value
        p = self._op(["item", "edit", item, "--vault", vault], input_text=json.dumps(doc), what="op item edit")
        if p.returncode != 0:
            first = (p.stderr.strip().splitlines() or ["unknown error"])[0]
            raise NasError(f"op item edit {item!r}: {first}")

    # --- OS keychain ----------------------------------------------------------

    def store_kind(self) -> str | None:
        want = self.cfg.get("store") or ""
        if want == "auto":
            if self.platform == "darwin" and self.which("security"):
                return "keychain"
            if self.platform.startswith("linux") and self.which("secret-tool"):
                return "secret-tool"
            return None
        if want in ("keychain", "secret-tool"):
            return want if self.which("security" if want == "keychain" else "secret-tool") else None
        return None

    def _svc(self) -> str:
        return self.cfg.get("store_service") or "synology-nas-cli"

    def store_read(self, user: str | None = None) -> tuple | None:
        """(user, password) from the keychain entry, or None."""
        kind = self.store_kind()
        if not kind:
            return None
        svc = self._svc()
        if kind == "keychain":
            if not user:
                p = self.run(["security", "find-generic-password", "-s", svc], capture_output=True, text=True)
                m = re.search(r'"acct"<blob>="([^"]*)"', p.stdout or "") if p.returncode == 0 else None
                if not m:
                    return None
                user = m.group(1)
            p = self.run(["security", "find-generic-password", "-s", svc, "-a", user, "-w"],
                         capture_output=True, text=True)
        else:
            if not user:
                p = self.run(["secret-tool", "search", "service", svc], capture_output=True, text=True)
                m = re.search(r"attribute\.account = (.+)", (p.stdout or "") + (p.stderr or ""))
                if not m:
                    return None
                user = m.group(1).strip()
            p = self.run(["secret-tool", "lookup", "service", svc, "account", user], capture_output=True, text=True)
        if p.returncode != 0 or not p.stdout:
            return None
        return user, p.stdout.rstrip("\r\n")

    def store_write(self, user: str, password: str, service: str | None = None) -> str:
        kind = self.store_kind()
        if not kind:
            raise NasError("no keychain available: macOS needs `security`, Linux needs `secret-tool` "
                           "(libsecret-tools); credentials.store must not be empty")
        svc = service or self._svc()
        if kind == "keychain":
            cmd = (f"add-generic-password -U -s {_quote_security(svc)} -a {_quote_security(user)} "
                   f"-l {_quote_security(svc)} -w {_quote_security(password)}\n")
            p = self.run(["security", "-i"], input=cmd, capture_output=True, text=True)
        else:
            p = self.run(["secret-tool", "store", f"--label={svc}", "service", svc, "account", user],
                         input=password, capture_output=True, text=True)
        if p.returncode != 0:
            raise NasError(f"{kind}: could not store the password ({(p.stderr or '').strip()[:200]})")
        return kind

    def store_delete(self, user: str | None = None) -> bool:
        kind = self.store_kind()
        if not kind:
            return False
        found = self.store_read(user)
        if not found:
            return False
        svc, user = self._svc(), found[0]
        if kind == "keychain":
            p = self.run(["security", "delete-generic-password", "-s", svc, "-a", user], capture_output=True, text=True)
        else:
            p = self.run(["secret-tool", "clear", "service", svc, "account", user], capture_output=True, text=True)
        return p.returncode == 0

    # --- the chain ------------------------------------------------------------

    def _command(self) -> str:
        return self.environ.get("NAS_PASSWORD_COMMAND") or self.cfg.get("password_command") or ""

    def source(self) -> str:
        """Name of the source that supplies the password (see the module docstring)."""
        if self._source:
            return self._source
        want = self.cfg.get("source") or "auto"
        if want != "auto":
            if want not in SOURCES:
                raise NasError(f"credentials.source {want!r}: use auto or one of {', '.join(SOURCES)}")
            self._source = want
            return want
        if self.cfg.get("op_password"):
            self._source = "op"
        elif self._command():
            self._source = "command"
        elif self.store_read(self.cfg.get("username") or None):
            self._source = "keychain"
        elif self.environ.get("NAS_PASSWORD"):
            self._source = "env"
        elif self.isatty():
            self._source = "prompt"
        else:
            raise InputRequired(
                "no DSM credentials configured and no prompt possible (--no-input, NAS_NO_INPUT or no terminal). Pick one: credentials.op_password (1Password), "
                "NAS_PASSWORD_COMMAND / credentials.password_command, `nas login --save` (keychain), "
                "NAS_USER + NAS_PASSWORD, or run in a terminal to be prompted. See README 'Credentials'.")
        return self._source

    def username(self) -> str:
        if self.cfg.get("username"):
            return self.cfg["username"]
        src = self.source()
        if src == "op":
            if not self.cfg.get("op_username"):
                raise NasError("credentials.op_password is set but neither credentials.username nor "
                               "credentials.op_username is")
            return self.op_read(self.cfg["op_username"])
        if self.cfg.get("op_username"):
            return self.op_read(self.cfg["op_username"])
        if src == "keychain":
            found = self.store_read()
            if found:
                self._store_user = found[0]
                return found[0]
        if self.isatty():
            sys.stderr.write("DSM user: ")
            sys.stderr.flush()
            user = sys.stdin.readline().strip()
            if user:
                return user
        raise InputRequired("no DSM username and no prompt possible: set NAS_USER or credentials.username")

    def password(self, user: str | None = None) -> str:
        if self._password is not None:
            return self._password
        src = self.source()
        if src == "op":
            if not self.cfg.get("op_password"):
                raise NasError("credentials.source is op but credentials.op_password is empty")
            return self.op_read(self.cfg["op_password"])
        if src == "command":
            cmd = self._command()
            if not cmd:
                raise NasError("credentials.source is command but no NAS_PASSWORD_COMMAND / password_command is set")
            try:
                p = self.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            except subprocess.TimeoutExpired:
                raise NasError("password command did not finish within 60 s")
            if p.returncode != 0 or not p.stdout.strip():
                first = ((p.stderr or "").strip().splitlines() or ["no output"])[0]
                raise NasError(f"password command failed (exit {p.returncode}): {first}")
            return p.stdout.splitlines()[0]  # `pass show` and friends put the password on line 1
        if src == "keychain":
            found = self.store_read(user or self.cfg.get("username") or self._store_user)
            if not found:
                raise NasError(f"no keychain entry for service {self._svc()!r}; run `nas login --save`")
            return found[1]
        if src == "env":
            v = self.environ.get("NAS_PASSWORD")
            if not v:
                raise NasError("credentials.source is env but NAS_PASSWORD is empty")
            return v
        if not self.isatty():
            raise InputRequired("credentials.source is prompt but no prompt is possible (--no-input, NAS_NO_INPUT "
                                "or no terminal)")
        self._password = self.getpass(f"DSM password for {user or 'the account'}: ")
        return self._password

    def otp(self) -> str | None:
        if self.otp_once:
            code, self.otp_once = self.otp_once, None
            return code
        cmd = self.cfg.get("otp_command")
        if cmd:
            p = self.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            code = (p.stdout or "").strip()
            if p.returncode == 0 and code.isdigit():
                return code
            raise NasError(f"otp command failed or printed no digits (exit {p.returncode})")
        if self.source() == "op" and self.cfg.get("op_otp") and self.cfg.get("op_password"):
            vault, item, _ = parse_op_ref(self.cfg["op_password"])
            code = self.op_otp(vault, item)
            if code:
                return code
        if self.isatty():
            code = self.getpass("DSM 2-step verification code: ").strip()
            return code or None
        return None

    def remember(self, password: str) -> None:
        """Keep a new password in memory for the rest of this process (after a rotation)."""
        self._password = password

    def writable_store(self) -> str | None:
        """Where a rotated password can be written so the next run finds it: 'op', a keychain kind, or None."""
        src = self.source()
        if src == "op" and self.cfg.get("op_password"):
            return "op"
        if src == "keychain":
            return self.store_kind()
        return None

    def write_password(self, user: str, password: str) -> str:
        where = self.writable_store()
        if where == "op":
            self.op_write(self.cfg["op_password"], password)
        elif where in ("keychain", "secret-tool"):
            self.store_write(user, password)
        else:
            raise NasError("the password comes from a source this CLI cannot update "
                           f"({self.source()}); use 1Password or `nas login --save`")
        return where

    def read_back(self, user: str) -> str:
        """Read the stored password again from its store (bypassing the in-memory copy)."""
        where = self.writable_store()
        if where == "op":
            return self.op_read(self.cfg["op_password"])
        found = self.store_read(user)
        if not found:
            raise NasError("password not found in the keychain after writing it")
        return found[1]

    def describe(self) -> dict:
        try:
            src = self.source()
        except NasError:
            return {"source": None}
        out = {"source": src}
        if src == "op":
            ref = self.cfg.get("op_password") or ""
            try:
                vault, item, _ = parse_op_ref(ref)
                out["op_ref"] = f"op://{vault}/{item}"
            except NasError:
                out["op_ref"] = ref
        elif src == "keychain":
            out["store"] = f"{self.store_kind()} service {self._svc()!r}"
        elif src == "command":
            out["command"] = "NAS_PASSWORD_COMMAND" if self.environ.get("NAS_PASSWORD_COMMAND") else "credentials.password_command"
        return out
