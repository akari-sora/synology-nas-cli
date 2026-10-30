"""The JSON Schemas in schemas/ describe the real `--json` output: build outputs from fake DSM sessions and
validate them with a minimal stdlib validator (type, properties, required, additionalProperties, items, enum,
minimum, oneOf/anyOf, local $ref)."""
import json
import os
import sys
import types

import _env

from nas import alert, cli, commands, incident
from fakenas import FakeNas, FakeSession, args, ok

SCHEMAS = os.path.join(_env.ROOT, "schemas")
from jsonschema_min import validate  # noqa: E402


def check(name, value):
    with open(os.path.join(SCHEMAS, name + ".schema.json")) as f:
        schema = json.load(f)
    assert schema["$schema"].startswith("https://json-schema.org/") and schema["$id"].endswith(name), schema["$id"]
    value = json.loads(json.dumps(value, default=str))  # exactly what --json prints
    errs = validate(value, schema, schema)
    assert not errs, (name, errs[:5])
    # the validator itself must reject a broken document
    if isinstance(value, dict) and schema.get("required"):
        broken = dict(value)
        broken.pop(schema["required"][0])
        assert validate(broken, schema, schema), f"{name}: validator accepted a document without a required key"


_env.use_config({})


class Minimal:
    backend_name = "password"

    def __init__(self):
        self.backend = types.SimpleNamespace(origin="https://192.0.2.10:5001", account="ops")

    def describe(self):
        return {"backend": "password", "origin": self.backend.origin, "source": "op", "op_ref": "op://V/I",
                "session": "login"}

    def call(self, api, method, params=None, version=None, timeout=None):
        canned = {
            ("SYNO.Core.System", "info"): {"model": "DS000", "firmware_ver": "DSM 7.4.1-90080 Update 1", "ram_size": 8192,
                                           "time": "2026-10-30 12:00:00", "up_time": "26:03:01", "sys_temp": 41},
            ("SYNO.Core.Desktop.Initdata", "get"): {"Session": {"user": "ops", "is_admin": True, "hostname": "nas-test"}},
            ("SYNO.Storage.CGI.Storage", "load_info"): {
                "disks": [{"id": "sda", "longName": "Drive 1", "model": "HD000 ", "status": "normal", "smart_status": "normal",
                           "temp": 35, "size_total": "3000000000000", "unc": 0}],
                "storagePools": [{"id": "reuse_1", "status": "normal", "device_type": "shr", "size": {"used": "1", "total": "2"}}],
                "volumes": [{"id": "volume_1", "status": "normal", "fs_type": "btrfs", "atime_opt": "noatime",
                             "size": {"used": "1", "total": "2"}}]},
            ("SYNO.Core.ExternalDevice.UPS", "get"): {"enable": True, "model": "UPS", "status": "usb_ups_status_online",
                                                     "charge": 100, "runtime": 1800, "mode": "SLAVE"},
            ("SYNO.Core.System.Utilization", "get"): {"cpu": {"user_load": 3, "system_load": 1, "1min_load": 13,
                                                             "5min_load": 9, "15min_load": 7},
                                                     "memory": {"total_real": 8000000, "avail_real": 6000000,
                                                                "real_usage": 25, "swap_usage": 0}},
            ("SYNO.Core.SyslogClient.Log", "list"): {"items": [], "total": 0},
            ("SYNO.Core.Security.Firewall", "get"): {"enable_firewall": False, "profile_name": "default"},
        }
        d = canned.get((api, method))
        return {"ok": True, "data": d} if d is not None else {"ok": False, "error": {"code": 102}}

    def call_many(self, calls):
        return [self.call(c["api"], c["method"], c.get("params"), c.get("version")) for c in calls]


m = Minimal()
check("status", commands.status(m, cli.parse_args(["status"]))[1])
check("whoami", commands.whoami(m, cli.parse_args(["whoami"]))[1])
check("health", commands.health(m, cli.parse_args(["health"]))[1])
findings = alert.alert(m, cli.parse_args(["alert", "--no-update"]))[1]
assert any(f["code"] == "firewall_off" for f in findings), findings
check("alert", findings)

nas = FakeNas()
check("incident", incident.audit(FakeSession(nas), args())[1])
check("incident-fix", incident.fix(FakeSession(FakeNas()), args(action="fix", dry_run=True))[1])
applied = incident.fix(FakeSession(FakeNas()), args(action="fix", yes=True, i_know_snapshots_may_rotate=True))[1]
assert applied["results"] and applied["after"]
check("incident-fix", applied)
print(f"schema checks ok (python {sys.version.split()[0]})")
