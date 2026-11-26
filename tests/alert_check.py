"""Power-cycle alerts use the SMART attribute name (NVMe and ATA).

NVMe on DSM: ID 12 is Power On Hours, ID 11 is Power Cycles. ATA: ID 12 is
Power_Cycle_Count. A baseline that still holds ID 12 is hours on NVMe; the
first updating run adopts the cycle count without a false disk_power_cycled,
and an ATA increase in that same file is still reported.
"""
import json
import os
import sys

import _env

from nas import alert, cli

SYSINFO = {"firmware_ver": "DSM 7.4.1-90080 Update 1", "time": "2026-11-26 01:00:00", "up_time": "48:00:00"}
BOOT = alert._boot_time(SYSINFO)


def nvme(cycles, hours, cycle_name="Power Cycles", hours_name="Power On Hours"):
    # ID 12 first: the old code returned it and treated hours as power cycles.
    return {"smartInfo": [
        {"id": "12", "name": hours_name, "raw": str(hours)},
        {"id": "11", "name": cycle_name, "raw": str(cycles)},
        {"id": "13", "name": "Unsafe Shutdowns", "raw": "23"},
    ]}


def ata(cycles, hours=1000, cycle_name="Power_Cycle_Count"):
    return {"smartInfo": [
        {"id": "9", "name": "Power_On_Hours", "raw": str(hours)},
        {"id": "12", "name": cycle_name, "raw": cycles},
    ]}


NVME_DISK = {"id": "nvme0n1", "device": "/dev/nvme0n1", "serial": "2N4XXXXXXDLT",
             "longName": "M.2 Drive 1", "model": "ADATA LEGEND 710", "status": "normal", "smart_status": "normal"}
ATA_DISK = {"id": "sda", "device": "/dev/sda", "serial": "ATA123",
            "longName": "Drive 3", "model": "ST8000VN004", "status": "normal", "smart_status": "normal"}


class Box:
    def __init__(self, disks, smart):
        self.disks = disks
        self.smart = smart

    def call_many(self, calls):
        return [self._one(c) for c in calls]

    def _one(self, c):
        api = c["api"]
        if api == "SYNO.Core.System":
            return {"ok": True, "data": dict(SYSINFO)}
        if api == "SYNO.Core.Security.Firewall":
            return {"ok": True, "data": {"enable_firewall": True}}
        if api == "SYNO.Storage.CGI.Storage":
            return {"ok": True, "data": {"disks": self.disks, "storagePools": [], "volumes": []}}
        if api == "SYNO.Core.ExternalDevice.UPS":
            return {"ok": True, "data": {"enable": False}}
        if api == "SYNO.Core.Package":
            return {"ok": True, "data": {"packages": []}}
        if api == "SYNO.Core.Upgrade.Server":
            return {"ok": True, "data": {}}
        if api == "SYNO.Storage.CGI.Smart":
            return {"ok": True, "data": self.smart[(c.get("params") or {}).get("device")]}
        return {"ok": True, "data": {}}

    def call(self, api, method, params=None, version=None, timeout=None):
        if (api, method) == ("SYNO.Core.SyslogClient.Log", "list"):
            return {"ok": True, "data": {"items": [], "total": 0}}
        return {"ok": True, "data": {}}


def write_state(path, disks, by_name=False):
    body = {"created": "2026-11-25 01:00:00", "boot_time": BOOT, "disks": disks, "last_log_time": None}
    if by_name:
        body["power_cycle_by_name"] = True
    with open(path, "w", encoding="utf-8") as f:
        json.dump(body, f)


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def run(box, path, no_update=False):
    argv = ["alert", "--state", path] + (["--no-update"] if no_update else [])
    return alert.alert(box, cli.parse_args(argv))


def power_events(findings):
    other = [f for f in findings if f["level"] in ("warning", "critical") and f["code"] != "disk_power_cycled"]
    assert other == [], other
    return [f for f in findings if f["code"] == "disk_power_cycled"]


# --- attribute name, not SMART ID ------------------------------------------
assert alert._power_cycles(nvme(46, 24549)) == 46
assert alert._power_cycles(nvme("1,046", "24,549", cycle_name="power_cycles")) == 1046
assert alert._power_cycles(nvme(46, 24549, cycle_name="POWER CYCLE COUNT")) == 46
assert alert._power_cycles(nvme(46, 24549, cycle_name="Power-Cycle-Count")) == 46
assert alert._power_cycles({"smartInfo": [
    {"id": "12", "name": "Power On Hours", "raw": "24549"}]}) is None
assert alert._power_cycles(ata(123, 99999)) == 123
assert alert._power_cycles(ata("1,234", cycle_name="  Power_Cycle_Count  ")) == 1234
assert alert._id12_is_hours(nvme(46, 24549)) is True
assert alert._id12_is_hours(ata(123)) is False

# --- fresh baseline: hours may rise; only a cycle increase alerts ----------
fresh = os.path.join(_env.TMP, "fresh.json")
smart = {"/dev/nvme0n1": nvme(46, 24549)}
box = Box([NVME_DISK], smart)
_, findings, rc = run(box, fresh)
assert power_events(findings) == [] and rc == 0, findings
saved = load(fresh)
assert saved["power_cycle_by_name"] is True
assert saved["disks"]["2N4XXXXXXDLT"]["power_cycle"] == 46

smart["/dev/nvme0n1"] = nvme(46, 24550)
_, findings, rc = run(box, fresh)
assert power_events(findings) == [] and rc == 0, findings
assert load(fresh)["disks"]["2N4XXXXXXDLT"]["power_cycle"] == 46

smart["/dev/nvme0n1"] = nvme(47, 24551)
_, findings, rc = run(box, fresh)
got = power_events(findings)
assert rc == 1 and len(got) == 1, findings
assert got[0]["message"].startswith("M.2 Drive 1 (ADATA LEGEND 710) power-cycled 1×"), got
assert "did not reboot" in got[0]["message"]
assert load(fresh)["disks"]["2N4XXXXXXDLT"]["power_cycle"] == 47

# --- legacy ID-12 baseline (the reported hours value, and a young drive) ---
# Reported shape: stored hours are far above the cycle count. The count drop
# is not an alert, and the file then holds the cycle count.
reported = os.path.join(_env.TMP, "reported.json")
write_state(reported, {
    "2N4XXXXXXDLT": {"slot": None, "name": "M.2 Drive 1", "model": "ADATA LEGEND 710", "power_cycle": 24549},
})
smart["/dev/nvme0n1"] = nvme(46, 24550)
_, findings, rc = run(box, reported)
assert power_events(findings) == [] and rc == 0, findings
saved = load(reported)
assert saved["power_cycle_by_name"] is True
assert saved["disks"]["2N4XXXXXXDLT"]["power_cycle"] == 46

# Young drive: cycle count is already above the stored hours, which used to
# raise one more false alert. ATA in the same file still reports a real increase.
young = os.path.join(_env.TMP, "young.json")
write_state(young, {
    "2N4XXXXXXDLT": {"slot": None, "name": "M.2 Drive 1", "model": "ADATA LEGEND 710", "power_cycle": 10},
    "ATA123": {"slot": None, "name": "Drive 3", "model": "ST8000VN004", "power_cycle": 100},
})
smart = {"/dev/nvme0n1": nvme(46, 12), "/dev/sda": ata(102, 5000)}
box = Box([NVME_DISK, ATA_DISK], smart)
before = open(young, encoding="utf-8").read()
_, findings, rc = run(box, young, no_update=True)
got = power_events(findings)
assert rc == 1 and len(got) == 1, findings
assert got[0]["message"].startswith("Drive 3 (ST8000VN004) power-cycled 2×"), got
assert open(young, encoding="utf-8").read() == before

_, findings, rc = run(box, young)
got = power_events(findings)
assert rc == 1 and len(got) == 1 and got[0]["message"].startswith("Drive 3 (ST8000VN004) power-cycled 2×"), findings
saved = load(young)
assert saved["power_cycle_by_name"] is True
assert saved["disks"]["2N4XXXXXXDLT"]["power_cycle"] == 46
assert saved["disks"]["ATA123"]["power_cycle"] == 102

smart["/dev/nvme0n1"] = nvme(46, 13)
smart["/dev/sda"] = ata(102, 5001)
_, findings, rc = run(box, young)
assert power_events(findings) == [] and rc == 0, findings
assert load(young)["disks"]["2N4XXXXXXDLT"]["power_cycle"] == 46

smart["/dev/nvme0n1"] = nvme(48, 14)
_, findings, rc = run(box, young)
got = power_events(findings)
assert rc == 1 and len(got) == 1, findings
assert got[0]["message"].startswith("M.2 Drive 1 (ADATA LEGEND 710) power-cycled 2×"), got
assert load(young)["disks"]["2N4XXXXXXDLT"]["power_cycle"] == 48
assert load(young)["disks"]["ATA123"]["power_cycle"] == 102

print(f"alert power-cycle checks ok (python {sys.version.split()[0]})")
