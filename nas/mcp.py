"""`nas mcp`: a Model Context Protocol server over stdio.

JSON-RPC 2.0, one message per line on stdin/stdout (stdout carries nothing else; diagnostics go to
stderr). Each tool runs the matching `nas` command with the same arguments and returns the same JSON
as `nas --json <command>` as text content; `_meta.exit_code` is the exit status the command would
have. Prompts answer with exit code 3 (`--no-input`). `incident_fix` returns the plan, or applies it
when the call has `"confirm": true` or the server runs with `--auto-confirm` / NAS_YES=1.
"""

from __future__ import annotations

import contextlib
import json
import sys
import traceback

from . import __version__, alert, commands, config, incident, manage
from .errors import NasError, set_no_input

PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]

INSTRUCTIONS = (
    "Tools wrap the `nas` CLI for one Synology NAS (DSM 7). Start with doctor; setup writes the config and returns "
    "{missing: [{field, why, ask_user}]} for anything a person provides. Results are the JSON of `nas --json "
    "<command>`; _meta.exit_code is the CLI exit status (0 ok, 1 findings/failure, 3 input needed, 4 login failed, "
    "5 AutoBlock, 6 unreachable, 7 certificate changed). incident_fix returns the plan; confirm: true (or a server "
    "started with --auto-confirm) applies it. DSM's AutoBlock blocks an address after 10 failed logins in 5 minutes."
)

READ = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
WRITE = {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False}


def _obj(props: dict | None = None, required: list | None = None) -> dict:
    s = {"type": "object", "properties": props or {}, "additionalProperties": False}
    if required:
        s["required"] = required
    return s


_LIST = {"oneOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]}

# name -> (description, input schema, annotations, argv builder)
TOOLS = {
    "setup": ("Write the config and sign in once (pins the certificate). Returns {missing: [{field, why, ask_user}]} "
              "with exit_code 3 when a value is needed from a person; relay ask_user and call again with the answer.",
              _obj({"origin": dict(_LIST, description="DSM address(es), e.g. https://192.168.0.10:5001"),
                    "user": {"type": "string"},
                    "password_source": {"type": "string", "description": "op:op://VAULT/ITEM/FIELD | command:CMD | "
                                        "keychain | env"},
                    "otp_source": {"type": "string", "description": "op | command:CMD | none"},
                    "otp_code": {"type": "string", "description": "current 2-step code for this login"},
                    "trust_device": {"type": "boolean", "description": "store DSM's trusted-device token"},
                    "tls": {"type": "string", "enum": ["pin", "verify"]},
                    "allowed_network": {"type": "array", "items": {"type": "string"},
                                        "description": "networks for the firewall/AutoBlock fixes, e.g. 192.168.0.0/24"},
                    "stage_dir": {"type": "string", "description": "folder in a writable share for --deep / alert-deploy"},
                    "webhook_file": {"type": "string"}}), WRITE,
              lambda a: ["setup"] + [x for o in ([a["origin"]] if isinstance(a.get("origin"), str) else a.get("origin") or [])
                                     for x in ("--origin", o)] + _opt(a, "user") + _opt(a, "password_source")
              + _opt(a, "otp_source") + _opt(a, "otp_code") + _flag(a, "trust_device") + _opt(a, "tls")
              + [x for n in a.get("allowed_network") or [] for x in ("--allowed-network", n)]
              + _opt(a, "stage_dir") + _opt(a, "webhook_file")),
    "doctor": ("Check config, credential source, origin reachability, TLS pin, login (one attempt), DSM version vs "
               "advisories, 2-step verification, backend capabilities and NAS clock. Each check: {name, status, "
               "detail, next_step}.", _obj(), READ, lambda a: ["doctor"]),
    "whoami": ("Sign in and show backend, origin, credential source, account, admin flag and DSM version.",
               _obj(), READ, lambda a: ["whoami"]),
    "status": ("Model, DSM version, uptime and the SA-26:13 verdict.", _obj(), READ, lambda a: ["status"]),
    "health": ("Disks (SMART, temperature), storage pools, volumes, UPS, CPU and memory.", _obj(), READ,
               lambda a: ["health"]),
    "net": ("Network interfaces, PPPoE (public address), firewall state, gateway.", _obj(), READ, lambda a: ["net"]),
    "services": ("SSH, FTP, SMB, AFP, NFS, rsync, QuickConnect, AutoBlock and DSM ports.", _obj(), READ,
                 lambda a: ["services"]),
    "logs": ("Connection-log summary: failed sign-ins by user and address, successful sign-ins from outside "
             "the LAN.",
             _obj({"since": {"type": "string", "description": "YYYY-MM-DD or 'YYYY-MM-DD HH:MM' (NAS time)"},
                   "limit": {"type": "integer", "minimum": 1, "description": "entries to read, newest first"},
                   "top": {"type": "integer", "minimum": 1}}), READ,
             lambda a: ["logs"] + _opt(a, "since") + _opt(a, "limit") + _opt(a, "top")),
    "alert": ("One pass of the health and security checks (baseline not updated). Result: list of findings "
              "{level, code, kind, message}; empty list = all clear.",
              _obj({"window": {"type": "integer", "minimum": 1, "description": "minutes of connection log"},
                    "failed_threshold": {"type": "integer", "minimum": 0}}), READ,
              lambda a: ["alert", "--no-update"] + _opt(a, "window") + _opt(a, "failed_threshold")),
    "incident_audit": ("Read-only audit against the C3RB3R/.L0CK3D ransomware campaign: PASS/WARN/FAIL/SKIP "
                       "per item with a hint. probe opens TCP connections to the public address; scan runs a "
                       "File Station search for ransom notes (minutes, creates temporary search tasks).",
                       _obj({"probe": {"type": "boolean"}, "scan": {"type": "boolean"},
                             "deep": {"type": "boolean", "description": "indicators of compromise via a read-only "
                                      "root script (temporary Task Scheduler task)"},
                             "hours": {"type": "integer", "minimum": 1},
                             "failed_threshold": {"type": "integer", "minimum": 0}}), READ,
                       lambda a: ["incident"] + _flag(a, "probe") + _flag(a, "scan") + _flag(a, "deep") + _opt(a, "hours")
                       + _opt(a, "failed_threshold")),
    "incident_fix": ("Hardening for the C3RB3R/.L0CK3D campaign: the plan (each change current -> new, the API calls, "
                     "the DSM UI path); with confirm: true (or a server started with --auto-confirm) it is applied, "
                     "every change read back and the audit run again. force_firewall / force_admin / force apply "
                     "changes whose checks do not pass (the check results stay in the notes). Fix names: "
                     + ", ".join(incident.FIX_ORDER) + ".",
                     _obj({"confirm": {"type": "boolean", "description": "true applies the plan"},
                           "only": dict(_LIST, description="fix names to include"),
                           "skip": dict(_LIST, description="fix names to leave out"),
                           "share": {"type": "array", "items": {"type": "string"}},
                           "ransom_scan": {"type": "boolean", "description": "a clean scan allows snapshot fixes"},
                           "i_know_snapshots_may_rotate": {"type": "boolean"},
                           "upgrade": {"type": "boolean", "description": "install the newest DSM (reboots)"},
                           "rotate_password": {"type": "boolean"},
                           "force_firewall": {"type": "boolean"}, "force_admin": {"type": "boolean"},
                           "force": {"type": "boolean"}}), WRITE,
                     lambda a: ["incident", "fix", "--yes" if a.get("confirm") or a.get("_auto") else "--dry-run"]
                     + _flag(a, "force_firewall") + _flag(a, "force_admin") + _flag(a, "force")
                     + _csv(a, "only") + _csv(a, "skip") + [x for s in a.get("share") or [] for x in ("--share", s)]
                     + _flag(a, "ransom_scan") + _flag(a, "i_know_snapshots_may_rotate") + _flag(a, "upgrade")
                     + _flag(a, "rotate_password")),
    "pkg_list": ("Installed packages: version, status, volume, whether they can be stopped.", _obj(), READ,
                 lambda a: ["pkg", "list"]),
    "volume_list": ("Volumes: status, file system, atime, capacity warning.", _obj(), READ,
                    lambda a: ["volume", "list"]),
    "tailscale_status": ("Tailscale package status, tailnet addresses and key expiry.", _obj(), READ,
                         lambda a: ["tailscale", "status"]),
    "api_read": ("Call a DSM Web API read method (get, list, load, info, query, status, ...) and return its data.",
                 _obj({"api": {"type": "string", "description": "e.g. SYNO.Core.System"},
                       "method": {"type": "string", "description": "e.g. info"},
                       "params": {"type": "object", "description": "parameters; non-JSON strings are quoted"},
                       "version": {"type": "integer", "minimum": 1}}, ["api", "method"]), READ,
                 lambda a: ["api", a["api"], a["method"]] + _opt(a, "version")
                 + [f"{k}={v if isinstance(v, str) else json.dumps(v)}" for k, v in (a.get("params") or {}).items()]),
}


def _opt(a: dict, key: str) -> list:
    return [f"--{key.replace('_', '-')}", str(a[key])] if a.get(key) is not None else []


def _flag(a: dict, key: str) -> list:
    return [f"--{key.replace('_', '-')}"] if a.get(key) else []


def _csv(a: dict, key: str) -> list:
    v = a.get(key)
    if not v:
        return []
    return [f"--{key}", v if isinstance(v, str) else ",".join(v)]


def tool_list() -> list:
    return [{"name": n, "title": n.replace("_", " "), "description": d, "inputSchema": s, "annotations": ann}
            for n, (d, s, ann, _) in TOOLS.items()]


def _check_args(schema: dict, args) -> str | None:
    if not isinstance(args, dict):
        return "arguments must be an object"
    props = schema.get("properties", {})
    for k in schema.get("required", []):
        if k not in args:
            return f"missing argument {k!r}"
    for k, v in args.items():
        if k not in props:
            return f"unknown argument {k!r}"
        types = [o["type"] for o in props[k]["oneOf"]] if "oneOf" in props[k] else [props[k].get("type")]
        ok = {"string": isinstance(v, str), "boolean": isinstance(v, bool), "object": isinstance(v, dict),
              "integer": isinstance(v, int) and not isinstance(v, bool),
              "array": isinstance(v, list) and all(isinstance(x, str) for x in v)}
        if not any(ok.get(t) for t in types):
            return f"argument {k!r} must be {' or '.join(types)}"
    return None


class Server:
    def __init__(self, session_factory, auto_confirm: bool = False):
        self.session_factory = session_factory
        self.session = None
        self.auto_confirm = auto_confirm

    def _session(self):
        if self.session is None:
            self.session = self.session_factory()
        return self.session

    def close(self) -> None:
        if self.session is not None:
            try:
                self.session.close()
            except NasError:
                pass
            self.session = None

    def call_tool(self, name: str, args: dict) -> dict:
        from . import onboard
        from .cli import COMMANDS, parse_args
        argv = TOOLS[name][3](dict(args, _auto=self.auto_confirm))
        try:
            ns = parse_args(argv)
        except SystemExit:
            return self._error(f"invalid arguments for {name}", 2)
        if name == "api_read" and not commands.is_read_method(args["method"]):
            return self._error(f"{args['method']!r} is a write method; api_read calls read methods "
                               "(writes: nas api METHOD --allow-write)", 1)
        try:
            with contextlib.redirect_stdout(sys.stderr):  # stdout belongs to the protocol
                if ns.cmd == "setup":
                    ns.origin = ns.setup_origin
                    result = onboard.setup(ns)
                    self.close()
                    if result[1].get("written"):
                        config.load(result[1]["config"])  # the next tool uses what setup wrote
                elif ns.cmd == "doctor":
                    self.close()
                    result = onboard.doctor(ns)
                else:
                    result = COMMANDS[ns.cmd][0](self._session(), ns)
        except NasError as e:
            if e.exit_code in (4, 5, 6, 7):
                self.close()
            return self._error(str(e), e.exit_code)
        data, rc = result[1], (result[2] if len(result) > 2 else 0)
        text = json.dumps(data, ensure_ascii=False, indent=2, default=str)
        return {"content": [{"type": "text", "text": text}], "isError": False, "_meta": {"exit_code": rc}}

    @staticmethod
    def _error(msg: str, code: int) -> dict:
        return {"content": [{"type": "text", "text": msg}], "isError": True, "_meta": {"exit_code": code}}

    def handle(self, msg) -> dict | None:
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or "method" not in msg:
            return _rpc_error(msg.get("id") if isinstance(msg, dict) else None, -32600, "invalid request")
        mid, method, params = msg.get("id"), msg["method"], msg.get("params") or {}
        if "id" not in msg:  # notification
            return None
        if method == "initialize":
            want = params.get("protocolVersion")
            return _rpc_result(mid, {
                "protocolVersion": want if want in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "synology-nas-cli", "title": "Synology NAS (nas CLI)", "version": __version__},
                "instructions": INSTRUCTIONS})
        if method == "ping":
            return _rpc_result(mid, {})
        if method == "tools/list":
            return _rpc_result(mid, {"tools": tool_list()})
        if method == "tools/call":
            name, args = params.get("name"), params.get("arguments") or {}
            if name not in TOOLS:
                return _rpc_error(mid, -32602, f"unknown tool {name!r}")
            bad = _check_args(TOOLS[name][1], args)
            if bad:
                return _rpc_error(mid, -32602, bad)
            try:
                return _rpc_result(mid, self.call_tool(name, args))
            except Exception as e:  # a bug must not kill the server
                traceback.print_exc(file=sys.stderr)
                return _rpc_result(mid, self._error(f"internal error: {type(e).__name__}: {e}", 1))
        return _rpc_error(mid, -32601, f"method not found: {method}")


def _rpc_result(mid, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _rpc_error(mid, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def serve(infile, outfile, session_factory, auto_confirm: bool = False) -> int:
    """Answer requests from `infile` until EOF."""
    set_no_input(True)
    server = Server(session_factory, auto_confirm)

    def send(m):
        outfile.write(json.dumps(m, ensure_ascii=False) + "\n")
        outfile.flush()

    try:
        while True:
            line = infile.readline()
            if not line:
                break
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                send(_rpc_error(None, -32700, "parse error"))
                continue
            if isinstance(msg, list):
                send(_rpc_error(None, -32600, "batches are not supported"))
                continue
            reply = server.handle(msg)
            if reply is not None:
                send(reply)
    finally:
        server.close()
    return 0
