"""`nas setup` (write the config and sign in once) and `nas doctor` (check everything an automated run needs).

Both answer immediately. When something only a person can provide is missing, `setup` returns
{"missing": [{"field", "why", "ask_user"}]} with exit status 3; `ask_user` is a one-line question to relay.
A failed sign-in is reported once and not repeated (DSM's AutoBlock counts every failure).
"""

from __future__ import annotations

import copy
import datetime as dt
import email.utils
import json
import os
import platform
import select
import shlex
import shutil
import socket
import sys

from . import advisories, config
from .backends import (PasswordBackend, _host_port, describe_error, load_pins, open_session, origin_key)
from .credentials import Credentials, parse_op_ref
from .errors import (AuthFailed, Blocked, CertificateChanged, InputRequired, NasError, Unreachable, can_prompt)

SOURCES = ("op", "command", "keychain", "env", "prompt")


def _missing(field: str, why: str, ask: str) -> dict:
    return {"field": field, "why": why, "ask_user": ask}


ASK = {
    "origin": "What is the NAS's DSM address, for example https://192.168.0.10:5001?",
    "user": "Which DSM account should the tool sign in with (an administrator account)?",
    "password_source": ("Where does the DSM password come from: a 1Password reference (op://vault/item/field), a "
                        "command that prints it, or should it be stored in this computer's keychain?"),
    "password": "Please type the DSM password for the keychain (it is stored in the OS keychain, not in a file).",
    "otp": ("DSM asks for a 2-step verification code: what is the current 6-digit code (or an otp command / "
            "1Password item with the one-time password)?"),
    "op": "The 1Password CLI `op` is not installed here: install it, or choose another password source?",
}


def _read_stdin_line(timeout: float = 5.0) -> str | None:
    """One line from stdin without blocking forever (POSIX select; on Windows a plain read)."""
    try:
        if os.name == "posix":
            ready, _, _ = select.select([sys.stdin], [], [], timeout)
            if not ready:
                return None
        line = sys.stdin.readline()
    except (OSError, ValueError):
        return None
    return line.rstrip("\r\n") or None


def _load_file(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except ValueError as e:
        raise config.ConfigError(f"{path}: not valid JSON ({e})")
    if not isinstance(d, dict):
        raise config.ConfigError(f"{path}: the top level must be a JSON object")
    return d


def _write_file(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def setup(args):
    path = config.path(args.config) if args.config else config.config_path()[0]
    file_cfg = _load_file(path)
    new = copy.deepcopy(file_cfg)
    cred = new.setdefault("credentials", {})
    missing = []

    origins = [o.strip().rstrip("/") for x in (args.origin or []) for o in x.split(",") if o.strip()]
    origins = origins or list(file_cfg.get("origins") or [])
    if origins:
        new["origins"] = origins
    else:
        missing.append(_missing("origin", "no DSM address in the config or on the command line", ASK["origin"]))

    if args.tls:
        new.setdefault("tls", {})["verify"] = args.tls == "verify"
    if getattr(args, "allowed_network", None):
        import ipaddress
        try:
            new["allowed_networks"] = [str(ipaddress.ip_network(n, strict=False)) for n in args.allowed_network]
        except ValueError as e:
            raise NasError(f"--allowed-network: {e}")
    if getattr(args, "stage_dir", None):
        new.setdefault("deploy", {})["stage_dir"] = args.stage_dir.rstrip("/")
    if getattr(args, "webhook_file", None):
        new.setdefault("webhook", {})["file"] = args.webhook_file

    user = args.user or cred.get("username") or os.environ.get("NAS_USER") or ""
    src = args.password_source or ""
    kind, _, value = src.partition(":")
    if src and kind not in SOURCES:
        raise NasError(f"--password-source {src!r}: use op:op://VAULT/ITEM/FIELD, command:CMD, keychain, env or prompt")
    if args.save_to_keychain:
        kind, value = "keychain", ""
    if not kind:  # keep what the config already says
        if cred.get("op_password"):
            kind = "op"
        elif cred.get("password_command") or os.environ.get("NAS_PASSWORD_COMMAND"):
            kind = "command"
        elif cred.get("source") in SOURCES:
            kind = cred["source"]
    if kind == "op":
        ref = value or cred.get("op_password", "")
        try:
            vault, item, _ = parse_op_ref(ref)
        except NasError as e:
            raise NasError(f"--password-source op: {e}")
        cred.update(source="op", op_password=ref, password_command="")
        if not user and not cred.get("op_username"):
            cred["op_username"] = f"op://{vault}/{item}/username"
        if not shutil.which("op"):
            missing.append(_missing("password_source", "`op` (1Password CLI) not found on PATH", ASK["op"]))
    elif kind == "command":
        cmd = value or cred.get("password_command", "")
        cred.update(source="command", password_command=cmd)
        first = (shlex.split(cmd) or [""])[0] if cmd else ""
        if not cmd:
            missing.append(_missing("password_source", "command: needs the command", ASK["password_source"]))
        elif os.name == "posix" and not (shutil.which(first) or os.path.exists(first)):
            missing.append(_missing("password_source", f"command {first!r} not found",
                                    "Which command prints the DSM password on this computer?"))
    elif kind in ("keychain", "env", "prompt"):
        cred["source"] = kind
    else:
        missing.append(_missing("password_source", "no credential source configured", ASK["password_source"]))
    if user:
        cred["username"] = user
    elif kind != "op" and not cred.get("op_username"):
        missing.append(_missing("user", "no DSM account name", ASK["user"]))

    password = None
    if kind == "keychain" and args.save_to_keychain:
        password = _read_stdin_line() if args.password_stdin else None
        if password is None and can_prompt():
            import getpass
            password = getpass.getpass("DSM password (stored in the OS keychain): ") or None
        if password is None:
            missing.append(_missing("password", "--save-to-keychain needs the password (--password-stdin, or a "
                                    "terminal prompt)", ASK["password"]))
    elif kind == "keychain" and user and not Credentials(_merged(new)).store_read(user):
        missing.append(_missing("password", "no keychain entry for this account yet", ASK["password"]))
    elif kind == "env" and not os.environ.get("NAS_PASSWORD"):
        missing.append(_missing("password", "NAS_PASSWORD is not set", "What is the DSM password (it is passed "
                                "through the NAS_PASSWORD environment variable for this run)?"))
    elif kind == "prompt" and not can_prompt():
        missing.append(_missing("password", "password prompt chosen but input is off (no terminal or --no-input)",
                                ASK["password_source"]))

    otp = args.otp_source or ""
    okind, _, ovalue = otp.partition(":")
    if okind == "command":
        cred.update(otp_command=ovalue, op_otp=False)
    elif okind == "op":
        cred.update(otp_command="", op_otp=True)
    elif okind in ("none", "prompt"):
        cred.update(otp_command="", op_otp=False)
    elif otp:
        raise NasError(f"--otp-source {otp!r}: use op, command:CMD, prompt or none")

    if missing:
        lines = ["Missing (exit 3):"] + [f"  {m['field']}: {m['why']}\n    ask: {m['ask_user']}" for m in missing]
        return lines, {"missing": missing, "config": path}, InputRequired.exit_code

    try:
        _merged(new)  # validate before writing
    except config.ConfigError as e:
        raise NasError(str(e))
    _write_file(path, new)
    cfg = config.load(path)
    creds = Credentials(cfg)
    if password is not None:
        creds.store_write(user, password)
    if args.otp_code:
        creds.otp_once = args.otp_code
    b = PasswordBackend(cfg["origins"], creds, cfg, use_cache=False)
    b.trust_device = bool(args.trust_device)
    data = {"config": path, "written": True, "origin": None, "account": None, "credentials": creds.describe(),
            "tls": {"mode": "verify" if cfg["tls"]["verify"] else "pin"}, "login": None}
    try:
        b.login()
        info = b.call_many([{"api": "SYNO.Core.System", "method": "info", "version": 1}])[0]
        b.logout()
    except AuthFailed as e:
        data.update(origin=b.origin, login=f"failed: {e}")
        if getattr(e, "code", None) == 403:
            data["missing"] = [_missing("otp", "DSM requires a 2-step verification code for this account", ASK["otp"])]
            return [f"Config written to {path}.", "DSM asks for a 2-step verification code.",
                    f"  ask: {ASK['otp']}", "Then: nas setup --otp-code CODE --trust-device"], data, InputRequired.exit_code
        return [f"Config written to {path}.", f"Login failed once: {e}",
                "Not retried: each failure counts toward AutoBlock. Correct the credential source, then run "
                "`nas doctor`."], data, e.exit_code
    except (Blocked, Unreachable, CertificateChanged) as e:
        data.update(origin=b.origin, login=f"failed: {e}")
        return [f"Config written to {path}.", f"Login not possible: {e}"], data, e.exit_code
    pin = load_pins(config.path(cfg["tls"]["known_certs_file"])).get(origin_key(b.origin)) if not cfg["tls"]["verify"] else None
    data["tls"]["sha256"] = (pin or {}).get("sha256")
    data.update(origin=b.origin, account=b.account, login="ok",
                dsm=(info.get("data") or {}).get("firmware_ver") if info.get("ok") else None,
                next_steps=["nas doctor", "nas incident", "nas incident fix --dry-run"])
    lines = [f"Config written to {path} (mode 600).", f"Signed in to {b.origin} as {b.account}; logged out.",
             f"DSM: {data['dsm']}", "TLS: " + (f"certificate pinned (sha256 {data['tls']['sha256'][:16]}...)"
                                               if data["tls"].get("sha256") else data["tls"]["mode"]),
             "Next: nas doctor, then nas incident"]
    return lines, data, 0


def _merged(file_cfg: dict) -> dict:
    """Effective config for a dict that is not on disk yet (validation included)."""
    cfg = config._merge(config.DEFAULTS, file_cfg, "")
    cfg["origins"] = [o.rstrip("/") for o in cfg["origins"]]
    cfg["chrome_origins"] = cfg["chrome_origins"] or list(cfg["origins"])
    return cfg


# --- doctor ------------------------------------------------------------------------------------------------

def doctor(args, config_error: str | None = None):
    checks = []

    def add(name, status, detail, next_step=""):
        checks.append({"name": name, "status": status, "detail": detail, "next_step": next_step})

    cfg = config.get()
    setup_hint = "nas setup --origin https://NAS:5001 --user USER --password-source op:op://VAULT/ITEM/password"
    if config_error:
        add("config", "fail", config_error, "fix the file, or rewrite it: " + setup_hint)
    elif config.loaded_from():
        add("config", "ok", f"{config.loaded_from()} (valid)")
    else:
        add("config", "warn", "no config file; built-in defaults only", setup_hint)

    backend = args.backend
    creds = Credentials(cfg)
    cred_ok = False
    if backend == "password":
        try:
            src = creds.source()
            why, step = _source_state(creds, src, cfg)
            if why:
                add("credentials", "fail", why, step)
            else:
                d = creds.describe()
                add("credentials", "ok", f"source {src}" + (f" ({d.get('op_ref') or d.get('store') or d.get('command')})"
                                                             if len(d) > 1 else ""))
                cred_ok = True
        except NasError as e:
            add("credentials", "fail", str(e).split(". Pick one")[0],
                "Ask the human: " + ASK["password_source"] + " Then: nas setup --password-source ...")
    else:
        add("credentials", "skip", f"--backend {backend} signs in without stored credentials")

    reachable = None
    if backend == "password":
        if not cfg["origins"]:
            add("origin", "fail", "no origin configured", "Ask the human: " + ASK["origin"] + " Then: nas setup --origin URL")
        else:
            states = []
            for o in cfg["origins"]:
                host, port = _host_port(o)
                try:
                    socket.create_connection((host, port), timeout=cfg["connect_timeout"]).close()
                    states.append(f"{o} reachable")
                    reachable = reachable or o
                except OSError as e:
                    states.append(f"{o} {type(e).__name__}")
            if reachable:
                add("origin", "ok", "; ".join(states))
            else:
                add("origin", "fail", "; ".join(states), "Ask the human: is the NAS on and is this computer on its LAN or "
                    "VPN? (nas setup --origin URL to change the address)")

        if cfg["tls"]["verify"]:
            add("tls", "ok", "tls.verify: certificates are checked against the system CAs")
        elif reachable:
            pin = load_pins(config.path(cfg["tls"]["known_certs_file"])).get(origin_key(reachable))
            add("tls", "ok", f"{origin_key(reachable)} pinned (sha256 {pin['sha256'][:16]}..., first seen "
                f"{pin.get('first_seen')})" if pin else f"{origin_key(reachable)} not pinned yet; the first login "
                "trusts the certificate it presents")
        else:
            add("tls", "skip", "no reachable origin")

    sysinfo, session, needs_otp = None, None, False
    if backend != "password" or (cred_ok and reachable):
        try:
            session = open_session(backend)
            r = session.call("SYNO.Core.System", "info", version=1)
            if r.get("ok"):
                sysinfo = r["data"]
                where = session.describe()
                add("login", "ok", f"{where.get('backend')} via {where.get('origin') or ', '.join(where.get('origins') or [])}"
                    f" as {getattr(session.backend, 'account', None) or '-'} (session: {where.get('session', '-')})")
            else:
                add("login", "fail", "SYNO.Core.System info: " + describe_error("SYNO.Core.System", r), "nas whoami")
        except AuthFailed as e:
            needs_otp = getattr(e, "code", None) == 403
            add("login", "fail", f"{e} (single attempt, not retried)",
                "Ask the human for the current 2-step code, then: nas setup --otp-code CODE --trust-device"
                if needs_otp else "Correct the credential source (each failure counts toward AutoBlock), then: nas doctor")
        except Blocked as e:
            add("login", "fail", str(e), "Remove this computer's address from Control Panel > Security > Protection > "
                "Allow/Block List (from another address), then: nas doctor")
        except CertificateChanged as e:
            add("login", "fail", str(e), "Ask the human whether the DSM certificate was replaced; if yes: "
                f"nas trust --reset {origin_key(reachable) if reachable else 'ORIGIN'}")
        except NasError as e:
            add("login", "fail", str(e), "nas doctor (after fixing the reported problem)")
    else:
        add("login", "skip", "credentials or origin not ready")

    if sysinfo:
        v = advisories.dsm_verdict(sysinfo.get("firmware_ver", ""))
        add("dsm_version", "ok" if v["status"] == "patched" else "fail" if v["status"] in ("vulnerable", "no_fix_for_branch")
            else "warn", f"{sysinfo.get('firmware_ver')}: SA-26:13 {v['status']}",
            "" if v["status"] == "patched" else "nas upgrade --dry-run, then nas incident fix --upgrade")
    else:
        add("dsm_version", "skip", "needs a login")

    if needs_otp:
        add("two_factor", "fail", "the account requires a 2-step verification code at every login and no code source "
            "is configured", "Ask the human for the current code, then: nas setup --otp-code CODE --trust-device "
            "(or nas setup --otp-source command:'oathtool --totp -b SECRET')")
    elif session is not None and sysinfo is not None:
        acct = getattr(session.backend, "account", None)
        two = None
        if acct:
            u = session.call("SYNO.Core.User", "list", {"type": "local", "offset": 0, "limit": -1,
                                                       "additional": ["2fa_status"]}, version=1)
            two = next((x.get("2fa_status") for x in (u.get("data") or {}).get("users", []) if x.get("name") == acct),
                       None) if u.get("ok") else None
        dev = bool(acct and backend == "password" and session.backend._device_id(acct))
        add("two_factor", "ok", f"account {acct or '-'}: 2-step verification "
            f"{'on' if two else 'off' if two is not None else 'unknown'}"
            + ("; trusted-device token stored" if dev else ""))
    else:
        add("two_factor", "skip", "needs a login")

    cap = {"password": "all commands", "chrome": "no uploads (upgrade, alert-deploy) and no package web UIs (tailscale)",
           "local": "no uploads (upgrade) and no package web UIs; runs as root on the NAS"}[backend]
    extra = [f"python {platform.python_version()}", f"deploy.stage_dir {'set' if cfg['deploy']['stage_dir'] else 'empty'}"
             " (incident --deep, alert-deploy)", "webhook " + ("configured" if any(cfg["webhook"][k] for k in
                                                                                    ("op_item", "file", "command"))
                                                             else "not configured") + " (alert-deploy)"]
    add("capabilities", "ok", f"backend {backend}: {cap}; " + "; ".join(extra),
        "" if cfg["deploy"]["stage_dir"] else "for incident --deep / alert-deploy: set deploy.stage_dir to a folder in "
        "a writable share, e.g. /SHARE/.nas-cli-deploy")

    if session is not None and sysinfo is not None and backend == "password":
        try:
            st, hdr, _body, _c = session.http_raw("/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query"
                                                  "&query=SYNO.API.Auth", timeout=10)
            date = hdr.get("Date") or hdr.get("date")
            nas_utc = email.utils.parsedate_to_datetime(date) if date else None
            skew = (nas_utc - dt.datetime.now(dt.timezone.utc)).total_seconds() if nas_utc else None
            if skew is None:
                add("clock", "skip", "DSM sent no Date header")
            else:
                add("clock", "ok" if abs(skew) <= 120 else "warn", f"NAS clock {skew:+.0f} s from this computer",
                    "" if abs(skew) <= 120 else "Control Panel > Regional Options > Time: synchronize with an NTP "
                    "server (2-step codes and log times depend on it)")
        except (NasError, TypeError, ValueError) as e:
            add("clock", "skip", f"could not read the NAS clock ({e})")
    else:
        add("clock", "skip", "needs a password-backend login")

    if session is not None:
        try:
            session.close()
        except NasError:
            pass
    rc = 1 if any(c["status"] == "fail" for c in checks) else 0
    width = max(len(c["name"]) for c in checks)
    lines = []
    for c in checks:
        lines.append(f"{c['status'].upper():<5} {c['name']:<{width}}  {c['detail']}")
        if c["next_step"] and c["status"] != "ok":
            lines.append(f"{'':<{width + 7}}-> {c['next_step']}")
    return lines, {"checks": checks, "ok": rc == 0}, rc


def _source_state(creds: Credentials, src: str, cfg: dict) -> tuple:
    """(problem or None, next step) for a credential source, without reading the secret."""
    c = cfg["credentials"]
    if src == "op":
        if not shutil.which("op"):
            return "`op` (1Password CLI) not on PATH", "Ask the human: " + ASK["op"]
        tok = config.path(c.get("op_token_file") or "")
        if not (os.environ.get("OP_SERVICE_ACCOUNT_TOKEN") or (tok and os.path.isfile(tok))):
            return None, ""  # the signed-in 1Password app answers instead
        return None, ""
    if src == "command":
        cmd = os.environ.get("NAS_PASSWORD_COMMAND") or c.get("password_command") or ""
        first = (shlex.split(cmd) or [""])[0]
        if os.name == "posix" and not (shutil.which(first) or os.path.exists(first)):
            return f"password command {first!r} not found", "Which command prints the DSM password here? Then: " \
                                                              "nas setup --password-source command:CMD"
        return None, ""
    if src == "keychain":
        return None, ""
    if src == "env":
        return (None, "") if os.environ.get("NAS_PASSWORD") else ("NAS_PASSWORD is not set", "export NAS_PASSWORD (and NAS_USER)")
    if src == "prompt":
        return (None, "") if can_prompt() else ("password prompt needs a terminal", "nas setup --password-source "
                                                "op:REF|command:CMD|keychain")
    return f"unknown source {src}", "nas setup --password-source ..."
