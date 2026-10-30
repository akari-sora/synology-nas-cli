"""A fake DSM for offline tests: a vulnerable DSM 7.1 box whose writes change its state (see FakeNas.st)."""
import copy
import json
import types

from nas import incident

incident.time.sleep = lambda s: None  # no waiting on the fake NAS
incident.client_address = lambda origin: ("192.0.2.50", "192.0.2.10")  # LAN client, LAN origin
incident.fresh_login_error = lambda s: None
incident.get_proxies = lambda: {}

def ok(data):
    return {"ok": True, "data": data}


def err(code):
    return {"ok": False, "error": {"code": code}}


class FakeNas:
    """A vulnerable DSM 7.1 box with a public PPPoE address. Writes change `self.st`."""

    def __init__(self):
        self.st = {
            "fw_on": False,
            "profile": {"name": "default", "global": {"policy": "none", "rules": []},
                        "eth0": {"policy": "allow", "rules": []},
                        "pppoe": {"policy": "allow", "rules": [{"enable": True, "policy": "allow", "source_ip": "all",
                                                                "source_ip_group": "all", "ports": "5001"}]}},
            "qc": True, "qc_upnp": True, "ab": False, "ab_allow": set(), "smb_min": 0, "admin": "normal",
            "php": "running", "worm": {"photos": True, "docs": False},
            "sched": {"photos": (True, 5), "docs": (False, -1), "media": (False, 9)},
            "pf": [{"enable": True, "rule_id": 1, "ds_port": 5001, "router_port": 5001, "router_protocol": "tcp",
                    "serviceid": {"id": "dsm"}, "service_name": "DSM", "force": False}],
            "retention_set": {},
        }
        self.sent = []

    def handle(self, api, method, p):
        st = self.st
        log = (st.get("own_signin", [{"time": "2026/10/30 11:59:00",
                                      "descr": "User [ops] from [192.0.2.50] signed in to [DSM] successfully via [password]"}]) +
               [{"time": f"2026/10/30 11:{m:02d}:00", "descr": f"User [admin] from [203.0.113.{m}] failed to sign in"}
                for m in range(24, -1, -1)] +
               [{"time": "2026/10/29 23:51:00", "descr": "User [ops] from [1.2.3.4] signed in to [DSM] successfully via [password]"},
                {"time": "2026/10/29 22:00:00", "descr": "User [ops] from [192.0.2.50] signed in to [DSM] successfully via [password]"}])
        R = {
            ("SYNO.Core.System", "info"): ok({"firmware_ver": "DSM 7.1.1-42962 Update 9", "time": "2026-10-30 12:00:00"}),
            ("SYNO.Core.Package", "list"): ok({"packages": [
                {"id": "PHP7.4", "version": "7.4.33-0120", "additional": {"status": st["php"]}},
                {"id": "Calendar", "version": "3.0.4-21435", "additional": {"status": "running"}}]}),
            ("SYNO.Core.Security.Firewall", "get"): ok({"enable_firewall": st["fw_on"], "profile_name": "default"}),
            ("SYNO.Core.Security.Firewall.Profile", "get"): ok(copy.deepcopy(st["profile"])),
            ("SYNO.Core.Security.Firewall.Adapter", "list"): ok({"adapter_names": ["eth0", "global", "pppoe"]}),
            ("SYNO.Core.Network.PPPoE", "list"): ok([{"status": "connected", "ip": "203.0.113.7", "ipv6": []}]),
            ("SYNO.Core.Network.Interface", "list"): ok([{"ifname": "eth0", "ip": "192.0.2.10", "type": "lan"},
                                                         {"ifname": "pppoe", "ip": "203.0.113.7", "type": "pppoe"}]),
            ("SYNO.Core.Desktop.Initdata", "get"): ok({"Session": {"user": "ops", "is_admin": True}}),
            ("SYNO.Core.Group.Member", "list"): st.get("admins_resp", ok({"users": [{"name": "admin"}, {"name": "ops"}],
                                                                           "total": 2})),
            ("SYNO.Core.QuickConnect", "get"): ok({"enabled": st["qc"], "server_alias": "example"}),
            ("SYNO.Core.QuickConnect.Upnp", "get"): ok({"enabled": st["qc_upnp"]}),
            ("SYNO.Core.Security.AutoBlock", "get"): ok({"enable": st["ab"], "attempts": 10, "within_mins": 5, "expire_day": 0}),
            ("SYNO.Core.Security.AutoBlock.Rules", "list"): (
                ok({"ip_info": [{"ip": ip} for ip in sorted(st["ab_allow"])], "total": len(st["ab_allow"])})
                if p.get("type") == "allow" and not st.get("ab_list_broken") else err(103)),
            ("SYNO.Core.Security.AutoBlock.Rules", "get"): ok({"ip": p.get("ip"), "type": "allow" if isinstance(p.get("ip"), str) and "/" not in p["ip"] and p["ip"] in st["ab_allow"] else "none"}),
            ("SYNO.Core.FileServ.SMB", "get"): ok({"enable_samba": True, "smb_min_protocol": st["smb_min"], "smb_max_protocol": 3}),
            ("SYNO.Core.User", "list"): ok({"users": [{"name": "admin", "expired": st["admin"]}, {"name": "ops", "expired": "normal"}]}),
            ("SYNO.Core.User", "get"): ok({"users": [{"name": "admin", "expired": st["admin"]}]}),
            ("SYNO.Core.PortForwarding.Rules", "load"): ok({"rules": copy.deepcopy(st["pf"])}),
            ("SYNO.Core.Web.DSM", "get"): ok({"http_port": 5000, "https_port": 5001}),
            ("SYNO.Core.SyslogClient.Log", "list"): ok({"items": log if p.get("start") in (0, "0") else [], "total": len(log)}),
            ("SYNO.FileStation.List", "list_share"): ok({"shares": [{"name": n, "path": "/" + n} for n in ("photos", "docs", "media")]}),
            ("SYNO.DisasterRecovery.Retention", "info"): ok({"adv_features": ["lun_uuid_name", "trigger_by_time", "space_reclaim"]}),
            ("SYNO.DisasterRecovery.Retention", "get_worm_lock"): ok({"worm_lock_enable": st["worm"].get(p.get("name")), "worm_lock_day": 7}),
            ("SYNO.DisasterRecovery.Retention", "get"): ok({"name": p.get("name"), "policyType": 0, "retainDay": 7, "hourly": 24, "schedule": None, "tid": -1}),
        }
        if (api, method) == ("SYNO.Core.Share.Snapshot", "get_schedule"):
            on, tid = st["sched"][p["name"]]
            return ok({"enable_snapshot_schedule": on, "task_id": tid, "schedule": {
                "date": "2026/10/30", "date_type": 0, "week_name": "0,1,2,3,4,5,6", "hour": 2, "min": 0, "repeat": 0,
                "repeat_hour": 0, "repeat_min": 0, "last_work_hour": 2, "monthly_week": [], "next_trigger_time": "x",
                "repeat_hour_store_config": None}})
        if (api, method) == ("SYNO.Core.Share.Snapshot", "list"):
            snaps = [{"time": "GMT+01-2026.10.30-03.30.01", "schedule_snapshot": True}] if p["name"] == "photos" else []
            return ok({"snapshots": snaps})
        if (api, method) in R:
            return R[(api, method)]
        # writes
        if (api, method) == ("SYNO.Core.Security.Firewall.Profile", "set"):
            st["profile"] = copy.deepcopy(p["profile"])
            return ok(None)
        if (api, method) == ("SYNO.Core.Security.Firewall.Profile.Apply", "start"):
            st["fw_on"] = True
            return ok({"task_id": "@fw1"})
        if (api, method) == ("SYNO.Core.Security.Firewall.Profile.Apply", "status"):
            return ok({"finish": True, "success": True})
        if (api, method) == ("SYNO.Core.Security.Firewall.Profile.Apply", "stop"):
            return ok(None)
        if (api, method) == ("SYNO.Core.QuickConnect", "set"):
            st["qc"] = p["enabled"]
            return ok(None)
        if (api, method) == ("SYNO.Core.QuickConnect.Upnp", "set"):
            st["qc_upnp"] = p["enabled"]
            return ok(None)
        if (api, method) == ("SYNO.Core.Security.AutoBlock", "set"):
            st["ab"] = p["enable"]
            return ok(None)
        if (api, method) == ("SYNO.Core.Security.AutoBlock.Rules", "create"):
            st["ab_allow"] |= set(p["ip"])
            return ok(None)
        if (api, method) == ("SYNO.Core.FileServ.SMB", "set"):
            st["smb_min"] = p["smb_min_protocol"]
            return ok(None)
        if (api, method) == ("SYNO.Core.User", "set"):
            return err(105)  # what DSM answers from a password session, even after PasswordConfirm
        if (api, method) == ("SYNO.Core.User.PasswordConfirm", "auth"):
            return ok({"SynoConfirmPWToken": "t"})
        if (api, method) == ("SYNO.Core.TaskScheduler", "list"):
            return ok({"tasks": [{"id": i, "name": t["name"]} for i, t in st.setdefault("tasks", {}).items()]})
        if (api, method) == ("SYNO.Core.TaskScheduler.Root", "create"):
            tid = len(st.setdefault("tasks", {})) + 100
            st["tasks"][tid] = {"name": p["name"], "script": json.loads(p["extra"])["script"]}
            return ok({"id": tid})
        if (api, method) == ("SYNO.Core.TaskScheduler", "run"):
            script = st["tasks"][p["tasks"][0]["id"]]["script"]
            if "api=SYNO.Core.User method=set" in script and """name='"admin"'""" in script:
                st["admin"] = "now"  # synowebapi as root
            return ok(None)
        if (api, method) == ("SYNO.Core.TaskScheduler", "delete"):
            del st["tasks"][p["tasks"][0]["id"]]
            return ok(None)
        if (api, method) == ("SYNO.Core.Package.Control", "stop"):
            st["php"] = "stop"
            return ok(None)
        if (api, method) == ("SYNO.DisasterRecovery.Retention", "set_worm_lock"):
            st["worm"][p["name"]] = p["worm_lock_enable"]
            return ok(None)
        if (api, method) == ("SYNO.DisasterRecovery.Retention", "set"):
            st["retention_set"][p["name"]] = p
            return ok(None)
        if (api, method) == ("SYNO.Core.Share.Snapshot", "set_schedule"):
            st["sched"][p["name"]] = (p["enable_snapshot_schedule"], p["task_id"] if p["task_id"] != -1 else 99)
            return ok(None)
        if (api, method) == ("SYNO.Core.PortForwarding.Rules", "save"):
            st["pf"] = copy.deepcopy(p["rules"])
            return ok({"task_id": "PF1"})
        if (api, method) == ("SYNO.Core.PortForwarding.Rules", "save_status"):
            return ok({"status": "success"})
        return err(102)


class FakeSession:
    def __init__(self, nas, backend_name="password"):
        self.nas, self.backend_name = nas, backend_name
        self.backend = types.SimpleNamespace(origin="https://192.0.2.10:5001", account="ops",
                                             confirm_password=lambda: "t")

    def call(self, api, method, params=None, version=None, timeout=None):
        self.nas.sent.append((api, method))
        return self.nas.handle(api, method, params or {})

    def call_many(self, calls):
        return [self.call(c["api"], c["method"], c.get("params"), c.get("version")) for c in calls]


def args(**kw):
    a = dict(action=None, probe=False, scan=False, probe_timeout=1, scan_timeout=10, log_limit=1000, hours=24,
             failed_threshold=20, dry_run=False, yes=False, only=None, skip=None, share=None, upgrade=False,
             rotate_password=False, ransom_scan=False)
    a.update(kw)
    return types.SimpleNamespace(**a)


def status(items):
    return {i["id"]: i["status"] for i in items}
