"""Offline check of `nas mcp`: drive the server over pipes (JSON-RPC 2.0, one message per line) with a fake
DSM session; results must be the same JSON as `--json`, write tools only plan without confirm."""
import io
import json
import os
import sys
import threading
import types

import _env

from nas import incident, mcp
from nas.commands import is_read_method
from nas.errors import AuthFailed

incident.client_address = lambda origin: ("192.0.2.50", "192.0.2.10")
incident.get_proxies = lambda: {}
incident.fresh_login_error = lambda s: None
incident.time.sleep = lambda s: None


class FakeSession:
    backend_name = "password"

    def __init__(self):
        self.backend = types.SimpleNamespace(origin="https://192.0.2.10:5001", account="ops",
                                             describe=lambda: {"backend": "password"})
        self.sent, self.smb_min, self.closed = [], 0, False

    def describe(self):
        return {"backend": "password", "origin": self.backend.origin, "source": "env", "session": "login"}

    def call(self, api, method, params=None, version=None, timeout=None):
        self.sent.append((api, method))
        p = params or {}
        if (api, method) == ("SYNO.Core.System", "info"):
            return {"ok": True, "data": {"model": "DS000", "firmware_ver": "DSM 7.4.1-90080 Update 1",
                                         "time": "2026-10-30 12:00:00", "up_time": "1:00:00"}}
        if (api, method) == ("SYNO.Core.Desktop.Initdata", "get"):
            return {"ok": True, "data": {"Session": {"user": "ops", "is_admin": True, "hostname": "nas-test"}}}
        if (api, method) == ("SYNO.Core.FileServ.SMB", "get"):
            return {"ok": True, "data": {"enable_samba": True, "smb_min_protocol": self.smb_min, "smb_max_protocol": 3}}
        if (api, method) == ("SYNO.Core.FileServ.SMB", "set"):
            self.smb_min = p["smb_min_protocol"]
            return {"ok": True, "data": None}
        if (api, method) == ("SYNO.Core.SyslogClient.Log", "list"):
            return {"ok": True, "data": {"items": [], "total": 0}}
        return {"ok": False, "error": {"code": 102}}

    def call_many(self, calls):
        return [self.call(c["api"], c["method"], c.get("params"), c.get("version")) for c in calls]

    def close(self):
        self.closed = True


sessions = []


def factory():
    s = FakeSession()
    sessions.append(s)
    return s


r_in, w_in = os.pipe()
r_out, w_out = os.pipe()
server_in, client_out = os.fdopen(r_in, "r", encoding="utf-8"), os.fdopen(w_in, "w", encoding="utf-8")
client_in, server_out = os.fdopen(r_out, "r", encoding="utf-8"), os.fdopen(w_out, "w", encoding="utf-8")
t = threading.Thread(target=lambda: (mcp.serve(server_in, server_out, factory), server_out.close()), daemon=True)
t.start()
seq = [0]


def send(obj):
    client_out.write((obj if isinstance(obj, str) else json.dumps(obj)) + "\n")
    client_out.flush()


def rpc(method, params=None, notify=False):
    msg = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    if notify:
        send(msg)
        return None
    seq[0] += 1
    msg["id"] = seq[0]
    send(msg)
    reply = json.loads(client_in.readline())
    assert reply["id"] == seq[0] and reply["jsonrpc"] == "2.0", reply
    return reply


def call(name, **args):
    r = rpc("tools/call", {"name": name, "arguments": args})
    return r["result"]


r = rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}})
assert r["result"]["protocolVersion"] == "2025-06-18" and r["result"]["capabilities"] == {"tools": {"listChanged": False}}
assert r["result"]["serverInfo"]["name"] == "synology-nas-cli" and "AutoBlock" in r["result"]["instructions"]
assert rpc("initialize", {"protocolVersion": "1999-01-01"})["result"]["protocolVersion"] == mcp.PROTOCOL_VERSIONS[0]
rpc("notifications/initialized", notify=True)  # no reply expected
assert rpc("ping")["result"] == {}

tools = {x["name"]: x for x in rpc("tools/list")["result"]["tools"]}
assert set(tools) == {"setup", "doctor", "whoami", "status", "health", "net", "services", "logs", "alert",
                      "incident_audit", "incident_fix", "pkg_list", "volume_list", "tailscale_status", "api_read"}, set(tools)
for x in tools.values():
    low = x["description"].lower()
    assert not any(w in low for w in ("refused", "must not", "never ", "only the user", "be careful", "caution")), x["description"]
for x in tools.values():
    assert x["inputSchema"]["type"] == "object" and x["description"] and "readOnlyHint" in x["annotations"]
assert tools["incident_fix"]["annotations"]["destructiveHint"] is True and tools["status"]["annotations"]["readOnlyHint"]

# results are the --json data of the same command
res = call("status")
assert not res["isError"] and res["_meta"]["exit_code"] == 0
st = json.loads(res["content"][0]["text"])
assert st["firmware_ver"] == "DSM 7.4.1-90080 Update 1" and st["sa_26_13"]["status"] == "patched"
who = json.loads(call("whoami")["content"][0]["text"])
assert who["account"] == "ops" and who["hostname"] == "nas-test"
logs = json.loads(call("logs", since="2026-10-30 00:00", limit=100)["content"][0]["text"])
assert logs["since"] == "2026/10/30 00:00" and logs["fetched"] == 0
al = call("alert")
assert isinstance(json.loads(al["content"][0]["text"]), list) and al["_meta"]["exit_code"] in (0, 1)
aud = call("incident_audit")
assert "summary" in json.loads(aud["content"][0]["text"])

# incident_fix: plan only without confirm, applied with confirm
before = len(sessions[0].sent)
plan = json.loads(call("incident_fix", only="smb_min_protocol")["content"][0]["text"])
assert [c["fix"] for c in plan["plan"]] == ["smb_min_protocol"] and "results" not in plan
assert all(is_read_method(m) for _, m in sessions[0].sent[before:]), sessions[0].sent[before:]
done = call("incident_fix", only=["smb_min_protocol"], confirm=True)
applied = json.loads(done["content"][0]["text"])
assert applied["results"][0] == {"fix": "smb_min_protocol", "target": "SMB", "ok": True,
                                 "now": "min 1 max 3"}, applied["results"]
assert sessions[0].smb_min == 1 and len(sessions) == 1, "one session reused across calls"

# api_read: reads go through, writes are refused before anything is sent
rd = call("api_read", api="SYNO.Core.System", method="info", version=1)
assert json.loads(rd["content"][0]["text"])["model"] == "DS000"
before = len(sessions[0].sent)
wr = call("api_read", api="SYNO.Core.FileServ.SMB", method="set", params={"smb_min_protocol": 0})
assert wr["isError"] and "is a write method" in wr["content"][0]["text"] and len(sessions[0].sent) == before

# argument and protocol errors
assert rpc("tools/call", {"name": "status", "arguments": {"x": 1}})["error"]["code"] == -32602
assert rpc("tools/call", {"name": "logs", "arguments": {"limit": "ten"}})["error"]["code"] == -32602
assert rpc("tools/call", {"name": "api_read", "arguments": {"api": "SYNO.Core.System"}})["error"]["code"] == -32602
assert rpc("tools/call", {"name": "nope"})["error"]["code"] == -32602
assert rpc("resources/list")["error"]["code"] == -32601
send("{not json")
assert json.loads(client_in.readline())["error"]["code"] == -32700

# --auto-confirm: incident_fix applies without confirm
auto = mcp.Server(factory, auto_confirm=True)
res = json.loads(auto.call_tool("incident_fix", {"only": "smb_min_protocol"})["content"][0]["text"])
assert res.get("results") and res["results"][0]["ok"], res
# setup without anything configured: the missing-fields JSON, exit_code 3, no prompt
import tempfile
os.environ["NAS_CONFIG"] = os.path.join(tempfile.mkdtemp(), "c.json")
st = mcp.Server(factory).call_tool("setup", {})
body = json.loads(st["content"][0]["text"])
assert st["_meta"]["exit_code"] == 3 and not st["isError"] and {m["field"] for m in body["missing"]} >= {
    "origin", "password_source"}, body
assert all(m["ask_user"].endswith("?") or m["ask_user"].endswith(".") for m in body["missing"])
dr = mcp.Server(factory).call_tool("doctor", {})
assert dr["_meta"]["exit_code"] == 1 and "checks" in json.loads(dr["content"][0]["text"])
_env.use_config({})

# a login failure becomes an error result with the CLI exit code, and the next call opens a new session
def bad_factory():
    s = FakeSession()

    def boom(*a, **k):
        raise AuthFailed("DSM login failed: code 400: no such account or incorrect password")
    s.call = boom
    sessions.append(s)
    return s


srv = mcp.Server(bad_factory)
out = srv.call_tool("status", {})
assert out["isError"] and out["_meta"]["exit_code"] == 4 and srv.session is None

client_out.close()
t.join(5)
assert not t.is_alive() and sessions[0].closed, "EOF ends the server and closes the session"
print(f"mcp checks ok (python {sys.version.split()[0]})")
