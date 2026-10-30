"""Offline check of `alert --push`: what gets sent, dedupe, reminders, retries, alert_failed.

A local HTTP server stands in for the webhook receiver. Runs on Python 3.8
too (the NAS has 3.8.15): `python3.8 tests/push_check.py`.
"""
import datetime as dt
import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import _env  # noqa: E402,F401
from nas import alert  # noqa: E402

got, fail = [], [False]


class Hook(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers["Content-Length"])
        got.append((self.headers.get("Authorization"), json.loads(self.rfile.read(n))))
        self.send_response(500 if fail[0] else 200)
        self.end_headers()

    def log_message(self, *a):
        pass


srv = HTTPServer(("127.0.0.1", 0), Hook)
threading.Thread(target=srv.serve_forever, daemon=True).start()
d = tempfile.mkdtemp()
cfg = os.path.join(d, "webhook.json")
with open(cfg, "w") as f:
    json.dump({"url": f"http://127.0.0.1:{srv.server_port}/x", "header": "Authorization: Bearer TESTKEY"}, f)


class Args:
    push = cfg
    state = os.path.join(d, "baseline.json")


def W(code, msg, level="warning", kind="condition"):
    return {"level": level, "code": code, "kind": kind, "message": msg}


def run(fs):
    return alert.push(fs, Args, "2026-10-30 10:50:00")


def codes():
    return [f["code"] for f in got[-1][1]["findings"]]


pushed = os.path.splitext(Args.state)[0] + "-pushed.json"
alert.HEARTBEAT_HOUR = 24  # never due here; checked on its own at the end

assert run([W("disk_status", "Drive 2: crashed")]).startswith("push: sent 1")
assert got[-1][0] == "Bearer TESTKEY" and codes() == ["disk_status"]
n = len(got)
assert run([W("disk_status", "Drive 2: crashed")]) == "push: nothing new" and len(got) == n
run([W("disk_status", "Drive 2: crashed"), W("snapshot_stale", "photos: old"), W("nas_rebooted", "boot", "info", "event")])
assert codes() == ["snapshot_stale", "nas_rebooted"]
assert got[-1][1]["still_active"] == ["disk_status:Drive 2", "snapshot_stale:photos"], got[-1][1]
run([W("snapshot_stale", "photos: old")])
assert got[-1][1]["resolved"] == ["disk_status:Drive 2"] and got[-1][1]["findings"] == []
# a second subject under the same code is news; the first one is not repeated
run([W("snapshot_stale", "photos: old"), W("snapshot_stale", "media: old")])
assert [f["message"] for f in got[-1][1]["findings"]] == ["media: old"], got[-1][1]
run([W("snapshot_stale", "photos: old")])
assert got[-1][1]["resolved"] == ["snapshot_stale:media"]
st = json.load(open(pushed))
st["active"]["snapshot_stale:photos"]["sent"] = (dt.datetime.now() - dt.timedelta(hours=25)).isoformat(timespec="seconds")
json.dump(st, open(pushed, "w"))
run([W("snapshot_stale", "photos: old")])
assert [(f["code"], f["repeat"]) for f in got[-1][1]["findings"]] == [("snapshot_stale", True)]
fail[0] = True
assert "FAILED (HTTP 500)" in run([W("firewall_off", "off", "critical"), W("disk_missing", "Drive 2 gone", "warning", "event")])
fail[0] = False
# the event from the failed POST is sent again even though this run did not see it
run([W("firewall_off", "off", "critical")])
assert codes() == ["firewall_off", "disk_missing"] and got[-1][1]["resolved"] == ["snapshot_stale:photos"], got[-1][1]
n = len(got)
msgs = [alert.push_failure(Args, "boom") for _ in range(4)]
assert len(got) == n + 1 and codes() == ["alert_failed"], msgs
assert msgs[2] == "push: sent alert_failed" and "already sent" in msgs[3], msgs
run([W("firewall_off", "off", "critical")])
assert got[-1][1]["resolved"] == ["alert_failed"] and json.load(open(pushed))["failures"] == 0
# push state from before per-subject keys ({"disk_status": …}) is neither new nor resolved
st = json.load(open(pushed))
st["active"] = {"disk_status": {"level": "warning", "sent": dt.datetime.now().isoformat(timespec="seconds")}}
json.dump(st, open(pushed, "w"))
assert run([W("disk_status", "Drive 2: crashed")]) == "push: nothing new"
assert list(json.load(open(pushed))["active"]) == ["disk_status:Drive 2"]
run([W("firewall_off", "off", "critical")])

# daily heartbeat: sent once a day when nothing changed
alert.HEARTBEAT_HOUR = 0
st = json.load(open(pushed))  # any successful push counts as that day's heartbeat; pretend it was yesterday
st["heartbeat"] = (dt.datetime.now() - dt.timedelta(days=1)).isoformat(timespec="seconds")
json.dump(st, open(pushed, "w"))
n = len(got)
assert run([W("firewall_off", "off", "critical")]) == "push: sent heartbeat" and got[-1][1]["heartbeat"] is True
assert run([W("firewall_off", "off", "critical")]) == "push: nothing new" and len(got) == n + 1
# a corrupt push state is moved aside, not fatal
with open(pushed, "w") as f:
    f.write("{not json")
assert run([W("firewall_off", "off", "critical")]).startswith("push: sent") and os.path.exists(pushed + ".corrupt")
print(f"push checks ok (python {sys.version.split()[0]})")
