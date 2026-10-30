# `nas alert`, webhooks and deployment

## What `nas alert` reports

One pass of checks. Exit status 0 when nothing is at warning/critical level (info findings alone keep 0), 1 otherwise, anything else when DSM could not be reached or the login failed (reason on stderr).

`nas --json alert` prints the findings (an empty list means all clear). Each finding:

```json
{"level": "critical|warning|info", "code": "firewall_off", "kind": "condition|event", "message": "..."}
```

- `message` is at most 500 characters with control characters escaped (`\n`, `\x1b`, ...): account names and addresses in it come from the connection log, where whoever signs in chooses the account field.
- `kind: condition` is true right now and repeats on every run while it lasts.
- `kind: event` happened since the previous run and is reported once. Events come from the baseline file (`alert.state_file`): per-disk Power_Cycle_Count, the NAS boot time, and the newest connection-log entry already seen. The first run writes the baseline and reports no events. Keep the scheduled run in one place; for manual looks elsewhere use `--no-update` so the baseline is not touched.

| code | level | kind | when |
|---|---|---|---|
| `firewall_off` | critical | condition | DSM firewall off |
| `dsm_unpatched` | critical | condition | DSM build not in the SA-26:13 fixed list |
| `dsm_behind` | warning | condition | older than `latest_dsm` (only when set) |
| `dsm_update_available` | info | condition | Synology's update server offers an update |
| `disk_status` / `disk_smart` | warning | condition | a disk's status or SMART is not normal |
| `pool_status` / `volume_status` | warning | condition | a storage pool / volume is not normal |
| `disk_power_cycled` | warning | event | a disk's Power_Cycle_Count went up while the NAS did not reboot (or by more than 1): the drive lost power in its bay |
| `disk_missing` | warning | event | a disk seen last time is gone |
| `nas_rebooted` | info | event | boot time changed |
| `ups_on_battery` | critical | condition | UPS on battery |
| `ups_status` / `ups_charge_low` | warning | condition | UPS not online / charge below 50 % |
| `failed_signins` | warning | condition | more than `--failed-threshold` (20) failed sign-ins in `--window` (60) minutes |
| `external_signin` | critical | event | a successful sign-in from outside `allowed_networks` |
| `packages_off_volume1` | info | condition | packages installed outside `alert.package_volume` (only when set) |
| `camera_recording_stale` | warning | condition | a folder in `alert.recordings.folders` got no new file for `max_age_min` minutes |
| `snapshot_stale` | warning | condition | a share in `snapshot_shares` has no scheduled snapshot within `snapshot_max_age_hours` |
| `snapshot_schedule_off` | warning | condition | its snapshot schedule is off |
| `snapshot_worm_unsupported` | warning | condition | immutable-snapshot lock on, on a model without immutable snapshots (scheduled snapshots silently stop) |
| `tailscale_down` / `tailscale_key_expiring` | warning | condition | Tailscale package installed and not Running / node key expires within `--key-days` (14) |
| `firewall_unreadable` / `storage_unreadable` / `ups_unreadable` / `tailscale_unreadable` / `snapshot_unreadable` | warning/info | condition | that part could not be read |
| `alert_failed` | warning | condition | push only: the check itself failed 3 runs in a row |

Options: `--window 60`, `--since "YYYY-MM-DD HH:MM"`, `--failed-threshold 20`, `--log-limit 5000`, `--key-days 14`, `--state FILE`, `--no-update`, `--push FILE`.

## `--push FILE`: what gets sent

FILE is JSON: `{"url": "https://...", "header": "Name: value"}` (mode 600 recommended). The body is:

```json
{"source": "nas-alert", "host": "<config name>", "time": "<NAS clock>", "heartbeat": false,
 "findings": [{"level": "...", "code": "...", "kind": "...", "message": "...", "repeat": false}],
 "resolved": ["snapshot_stale:photos"], "still_active": ["disk_status:Drive 2"]}
```

- Sent: conditions that are new, warning/critical conditions still present after 24 h (`"repeat": true`), every event, and keys that cleared (`resolved`). The first run at or after 09:00 each day sends something even when nothing changed (`"heartbeat": true` when that is all it is), so a day without any POST means the check is not running.
- Deduplication key: the `code`; for camera, disk, pool, volume and snapshot codes it is `code:subject` (the part of the message before the first `:`), so a second disk or share going bad is news.
- A failed POST leaves the push state as it was and keeps the events in `pending_events`; the next run sends them again. A corrupt push state file is renamed to `.corrupt` and started fresh. Only one `--push` run at a time (a lock file next to the state).
- HTTP 200 counts as delivered. Anything else is a failure and is retried next run.

## Receivers

### Generic JSON receiver

Anything that accepts an HTTPS POST with a JSON body and checks one header. A minimal receiver, for illustration (put it behind a TLS reverse proxy):

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
import json, os

KEY = os.environ["NAS_WEBHOOK_KEY"]

class Hook(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.headers.get("Authorization") != f"Bearer {KEY}":
            self.send_response(401); self.end_headers(); return
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        for f in body.get("findings", []):
            print(body["host"], f["level"], f["code"], f["message"])   # forward to chat, email, ...
        self.send_response(200); self.end_headers()

HTTPServer(("127.0.0.1", 8080), Hook).serve_forever()
```

`webhook.json`: `{"url": "https://hooks.example.net/nas", "header": "Authorization: Bearer <key>"}`.

### Chat-bot routine webhook (Grok-Bot style)

Some chat assistants offer "routines" (scheduled tasks) with a webhook trigger: a URL plus a bearer key; each POST starts one assistant run with the body as input, and the assistant posts its summary in a chat. Facts that matter with `nas alert --push`:

- Each POST is one run and uses the assistant's quota (routines usually have an hourly cap), which is why `--push` only sends changes plus one daily heartbeat.
- A 200 answer means the run started, not that it finished.
- Setup: create the routine with a webhook trigger, copy its URL and key into `webhook.json` (`"header": "Authorization: Bearer <key>"`) or into a 1Password item (website = URL, a field named `header` holding the whole header line) and point `webhook.op_item` at it. Give the routine an instruction such as: "The input is JSON from `nas alert --push`: report new findings by level, say which keys resolved, and say nothing for a heartbeat with no findings."
- The key is often visible only in the routine's settings page, not to the assistant itself; rotate it there and re-run `nas alert-deploy`.

### No webhook: DSM's own notifications

DSM can notify by email and by mobile push (DS finder app) without any webhook: Control Panel > Notification (控制台 > 通知設定) > Email / Push Service, and the Rules tab picks which events. This covers DSM's own warning/error events (disk and pool failures, UPS on battery, AutoBlock blocking an address, backup and snapshot task failures). It does not cover the checks only `nas alert` makes (immutable-snapshot trap, stale scheduled snapshots, successful sign-ins from unexpected networks, Power_Cycle_Count jumps).

## Deployment

### Automatic: `nas alert-deploy`

From a computer with `--backend password` (an administrator account):

```bash
nas alert-deploy --test        # --interval 10, --webhook-item op://VAULT/ITEM, --no-dsm-webhook
```

1. Builds a tarball: `nas/*.py`, a `bin/nas` launcher and `config.json` (your effective config without `credentials`, `webhook` and `session`).
2. Uploads it to `deploy.stage_dir` (a folder inside a shared folder the account can write; the share's real path is looked up with File Station).
3. Creates a one-off root task that copies the tarball into `deploy.root_dir` (default `/volume1/@nas-alert`, root-only, not a shared folder), checks its SHA-256, extracts it to `app/`, writes `webhook.json` (mode 600, passed through stdin), runs one `alert --no-update` as a test, and writes `result.txt`. The task and the staging folder are deleted afterwards. The output shows `diff -r` against the previous install.
4. Creates the root task `deploy.task_name` running every `--interval` minutes:
   `NAS_CONFIG=<root>/app/config.json python3 <root>/app/bin/nas --backend local alert --state <root>/state/baseline.json --push <root>/webhook.json > <root>/state/last-run.txt 2>&1; exit 0`
   (`exit 0` because DSM marks a task failed on a non-zero exit and would send its own "task failed" mail on every warning.)
5. Creates or updates the DSM notification webhook `deploy.dsm_webhook_name` (rule template `deploy.dsm_webhook_template`, default `Warning`) pointing at the same URL with body `{"text": "@@TEXT@@"}` and prefix `deploy.dsm_webhook_prefix` (default `[name]`). `--test` sends DSM's test notification.

Creating root tasks requires DSM's password confirmation (`SYNO.Core.User.PasswordConfirm`), which uses the same credential chain. Re-run `alert-deploy` after changing the code or the config.

### Manual install on the NAS

The same result through the DSM web UI:

1. Put the code in a root-only folder. Upload the repository (at least `bin/nas` and `nas/`) with File Station to a shared folder, then create a one-off task (Control Panel > Task Scheduler > Create > Scheduled Task > User-defined script / 控制台 > 任務排程表 > 新增 > 排程的任務 > 使用者定義的指令碼, User: `root`) with:
   ```sh
   umask 077; mkdir -p /volume1/@nas-alert/state
   cp -r /volume1/SHARE/synology-nas-cli /volume1/@nas-alert/app && chown -R root:root /volume1/@nas-alert
   ```
   and run it once (select it > Run), then delete it. Code left inside a shared folder can be changed by every account that can write that share, and the scheduled task runs it as root.
2. Create `/volume1/@nas-alert/app/config.json` (at least `name`, `snapshot_shares`, `allowed_networks`) and `/volume1/@nas-alert/webhook.json` (`{"url": ..., "header": ...}`, `chmod 600`) the same way. Task scripts are visible to every administrator in Task Scheduler, so delete a task that contained the webhook key after it ran.
3. Create the scheduled task: User `root`, Schedule: Daily, repeat every 10 minutes from 00:00 to 23:50, User-defined script:
   ```sh
   D=/volume1/@nas-alert
   NAS_CONFIG="$D/app/config.json" python3 "$D/app/bin/nas" --backend local alert --state "$D/state/baseline.json" --push "$D/webhook.json" > "$D/state/last-run.txt" 2>&1
   exit 0
   ```
4. DSM's own events through the same webhook: Control Panel > Notification > Webhooks > Add (控制台 > 通知設定 > Webhook > 新增): Provider Custom, URL, method POST, header from `webhook.json`, body `{"text": "@@TEXT@@"}`, then choose the rules (the "Warning" template covers warning and error events). "Send test message" checks it.

### From another machine (cron / launchd)

`nas alert --push` with `--backend password` works from any always-on computer that reaches DSM. Use a non-interactive credential source (1Password service account, a password command) and run `nas login` once so runs reuse a cached session instead of signing in every 10 minutes.

cron (Linux):

```cron
*/10 * * * * NAS_CONFIG=$HOME/.config/synology-nas-cli/config.json $HOME/synology-nas-cli/bin/nas alert --push $HOME/.config/synology-nas-cli/webhook.json >> $HOME/.local/state/synology-nas-cli/alert.log 2>&1
```

launchd (macOS), `~/Library/LaunchAgents/net.example.nas-alert.plist`, loaded with `launchctl load`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>net.example.nas-alert</string>
  <key>ProgramArguments</key><array>
    <string>/Users/YOU/synology-nas-cli/bin/nas</string><string>alert</string>
    <string>--push</string><string>/Users/YOU/.config/synology-nas-cli/webhook.json</string>
  </array>
  <key>StartInterval</key><integer>600</integer>
  <key>StandardOutPath</key><string>/Users/YOU/Library/Logs/nas-alert.log</string>
  <key>StandardErrorPath</key><string>/Users/YOU/Library/Logs/nas-alert.log</string>
</dict></plist>
```

launchd and cron start with a minimal environment: anything the credential source needs (`OP_SERVICE_ACCOUNT_TOKEN` or the token file, `PATH` to `op`) has to be available there. A sleeping laptop misses runs; the daily heartbeat makes that visible.
