# DSM Web API notes

Behaviour of the DSM 7 Web API that this tool depends on, observed on DSM 7.1.1 and 7.4.1. Any call here can be made with `nas api NAME METHOD [k=v ...] [--version N] [--allow-write]`.

## Sign-in and requests

- `SYNO.API.Info query query=all` (no session needed) lists every API with its path, min/max version and `requestFormat`. When no version is given, `nas` tries the highest and steps down on 103/104 (method/version not supported).
- Login: `SYNO.API.Auth` v6 `login` with `account`, `passwd`, `session`, `format=sid`, `enable_syno_token=yes`. Every later request carries `_sid`; **the SynoToken is only accepted as a URL query parameter** (`...entry.cgi?SynoToken=...`). As an `X-SYNO-TOKEN` header or a form field DSM answers 119. Every login adds "User [x] from [ip] signed in to [DSM] successfully" to the connection log.
- 2-step verification: the first login answers 403; repeat it with `otp_code`. Add `enable_device_token=yes` and `device_name` to get `did` in the response; later logins send `device_id=<did>` + `device_name` and skip the code.
- `logout` with `session` and `_sid` ends the session.
- Logins right after a DSM upgrade answer 499 until post-upgrade tasks finish (`SYNO.Core.Desktop.SessionData getjs`, readable without a session, reports `dsm_upgrade_all_done`). 498 means an update is being installed.

Error codes (common / `SYNO.API.Auth`):

| Code | Meaning | What to do |
|---|---|---|
| 102 / 103 / 104 | API / method / version does not exist | Check `SYNO.API.Info`; try another `--version` |
| 105 | insufficient privilege | Use an administrator; some calls also need `SYNO.Core.User.PasswordConfirm` |
| 106 / 107 / 119 | session timeout / duplicate login / SID not found | Log in again. 119 on a fresh session usually means the SynoToken was not in the URL |
| 114 / 120 | missing / invalid parameter | Check names and JSON encoding (below) |
| 400 | wrong account or password | Fix the credential source; each failure counts toward AutoBlock |
| 401 | account disabled | |
| 403 | 2-step verification code required | Send `otp_code` |
| 404 | 2-step verification code wrong | Check clocks and the code source |
| 406 | 2-step verification enforced but not set up for the account | Enroll in the browser first |
| 407 | source address blocked by AutoBlock | Remove it from the block list from another address |
| 498 / 499 | upgrading / system not ready | Wait |

## Parameter encoding

- APIs whose `requestFormat` is `JSON` (almost all on DSM 7.4) JSON-decode every form field. A bare string such as `id=Tailscale` is not valid JSON: some APIs fall back to the raw text, others answer success and do nothing (`SYNO.Core.Package.Uninstallation`) or answer 120. `nas` quotes every value that does not parse as JSON, so `id=Tailscale` and `'id="Tailscale"'` both send `"Tailscale"`; numbers, `true`/`false`, lists and objects go as given.
- A field whose value must be *a string containing JSON* (for example `extra_values` of `Package.Uninstallation`, `req_param` of the notification webhook) has to be encoded twice. Sending the JSON object directly gives 120 or 4681.
- `synowebapi --exec` (below) JSON-decodes every field whatever `requestFormat` says.

## Running as root on the NAS: `synowebapi`

- DSM 7 ships `/usr/syno/bin/synowebapi`. As root: `synowebapi --exec api=SYNO.Core.System method=info version=1 [key=<JSON> ...]` runs the API without a session (runner `SYSTEM_ADMIN`). stdout starts with a banner line `[Line N] Exec WebAPI: ...`; the JSON reply starts at the first `{`.
- DSM 7 has Python 3.8 (`/bin/python3`, 3.8.15 on DSM 7.4.1). Code that runs on the NAS must avoid 3.9+ APIs.
- Root Task Scheduler tasks: `SYNO.Core.TaskScheduler.Root create` v4 with `name`, `owner=root`, `real_owner=root`, `enable`, `type=script`, `schedule` (a JSON *string*), `extra` (JSON string with `script`, `notify_enable`, `notify_mail`, `notify_if_error`) and `SynoConfirmPWToken`, which comes from `SYNO.Core.User.PasswordConfirm auth` v2 (`password`). Every N minutes all day: `{"date_type": 0, "week_day": "0,1,2,3,4,5,6", "hour": 0, "minute": 0, "repeat_hour": 0, "repeat_min": N, "last_work_hour": 23, "repeat_date": 1001, "monthly_week": "[]"}`.
- Script tasks that exit non-zero are marked failed (and DSM may mail about it): end scripts with `exit 0` when a non-zero status is not an error.
- `SYNO.Core.TaskScheduler run` **version 2** with `tasks=[{"id": N, "real_owner": "root"}]` runs a task now. Version 1 answers success and does not run it. Tasks whose `can_run` is false in `list` still run this way.
- `SYNO.Core.TaskScheduler delete` v2 `tasks=[{"id": N, "real_owner": "root"}]`.

## Firewall

- The connection log records each sign-in's source (`User [x] from [ip] signed in to [DSM] successfully via [password]`); that is the address the firewall has to allow for the current client. `SYNO.Core.CurrentConnection list_by_user username=X` lists live connections (the UI uses it before kicking sessions).

- `SYNO.Core.Security.Firewall get`: `enable_firewall`, `profile_name` (the active profile).
- `SYNO.Core.Security.Firewall.Profile list`: `profile_names`. `get` v1 takes `name` (with `profile_name` it answers 120) and returns one object per interface plus `name`: `{"global": {"policy": "none", "rules": [...]}, "eth0": {"policy": "drop", "rules": []}, "pppoe": {...}, "ppp0": {...}, "vpn": {...}, "wlan0": {...}}`. `SYNO.Core.Security.Firewall.Adapter list profile_name=...` lists the interface names.
- `policy` is what happens to traffic no rule matches: `allow` or `drop` (`none` on `global`). Rules in `global` apply to every interface.
- A rule: `{"enable": true, "log": false, "name": "", "policy": "allow", "port_direction": "destination", "port_group": "all", "ports": "all", "protocol": "all", "source_ip": "192.0.2.0/255.255.255.0", "source_ip_group": "netmask"}`. `source_ip_group` is `all` (with `source_ip: "all"`), `ip` (one address), `iprange` (`a-b`) or `netmask` (`address/mask`). The PPPoE "allow services" dialog writes rules with `source_ip: "all"`, which allow those ports from anywhere.
- Changing it: `SYNO.Core.Security.Firewall.Profile set` v1 `profile={...}` `profile_applying=false`, then `SYNO.Core.Security.Firewall.Profile.Apply start` v1 `name=<profile>` `profile_applying=false` (returns `task_id`), poll `status task_id=...` until `finish` / `success`, then `stop`. Applying the profile also turns the firewall on.
- Applying a default-deny profile cuts any session that reaches the NAS from an address the profile does not allow, including your own session through the public address. Apply it from an allowed address.
- Tailscale's DSM package in userspace networking mode (its default) delivers tailnet connections to DSM from `127.0.0.1`; the DSM firewall did not filter them in testing.

## AutoBlock

- `SYNO.Core.Security.AutoBlock get` / `set` v1: `enable`, `attempts`, `within_mins`, `enable_expire`, `expire_day` (`0` = blocks never expire). DSM's default is 10 attempts in 5 minutes.
- `SYNO.Core.Security.AutoBlock.Rules`: `list` (`type`, `offset`, `limit`; entries under `ip_info`), `get ip=...` (returns `type`: `allow`, `deny`, ...), `create` with `type=allow|deny`, `block_days` (0 = permanent), `overwrite=true`, `ip=[...]` (single addresses or `address/mask`).
- Allow-list `127.0.0.1` when using Tailscale in userspace mode: every tailnet device reaches DSM as `127.0.0.1`, so ten failed logins from any of them would block all of them.

## QuickConnect, router configuration

- `SYNO.Core.QuickConnect get` (`enabled`, `server_alias`, `region`); `set` v2 `enabled=false` turns it off (the UI uses v2 on DSM 7).
- `SYNO.Core.QuickConnect.Upnp get` / `set` v1 `enabled`: QuickConnect's automatic router port forwarding.
- `SYNO.Core.PortForwarding.Rules load` v1 lists the router rules DSM manages (UPnP/NAT-PMP, Control Panel > External Access > Router Configuration); errors when no router is configured. `save` v1 `rules=[{id, enable, rule_id, ds_port, router_port, router_protocol, serviceid, service_name, force}]` `task_id_suffix=PF` returns `task_id`; poll `save_status task_id=...`. (`serviceid` is the service's id string.)

## File services and accounts

- `SYNO.Core.FileServ.SMB get` / `set` v3: `smb_min_protocol` / `smb_max_protocol` with 0 = SMB1, 1 = SMB2, 2 = SMB2 + Large MTU, 3 = SMB3.
- `SYNO.Core.User list` v1 (`type=local`, `additional=["expired","2fa_status"]`): `expired` is `normal`, `now` (disabled) or a date `YYYY/M/D`. `SYNO.Core.User set` v1 `name=X expired=now` disables an account (the UI sends the same field).
- **`SYNO.Core.User set` answers 105 (insufficient privilege) from a password-login session, even for an administrator and even after `SYNO.Core.User.PasswordConfirm auth`.** As root it works: `/usr/syno/bin/synowebapi --exec api=SYNO.Core.User method=set version=1 name='"X"' expired='"now"'` inside a one-off `SYNO.Core.TaskScheduler.Root` task (create disabled, `SYNO.Core.TaskScheduler run` v2, delete). Reading it back with `SYNO.Core.User get` v1 `name=X additional=["expired"]` works from a normal session. `incident fix` disables the built-in `admin` this way (`selfmon.run_root_script`).
- Members of a group: `SYNO.Core.Group.Member list` v1 `group=administrators ingroup=true` (the UI's group dialog); `admin_check name=X` reports `is_admin` per user. `SYNO.Core.Desktop.Initdata get` v1 returns the session's account under `Session.user`.
- Your own password: `SYNO.Core.NormalUser set` v2 `password=<new>` `old_password=<old>` works from a normal session; `SYNO.Core.User set` answers 105 there too.
- `op read` (1Password CLI) fails on item names with non-ASCII characters; reference the item by ID.

## Snapshots (Snapshot Replication, Btrfs volumes)

- **Immutable-snapshot trap.** `SYNO.DisasterRecovery.Retention info` lists the model's `adv_features`; immutable snapshots (WORM) need `worm` in it. On models without it (an older model without immutable-snapshot support listed only `lun_uuid_name`, `trigger_by_time`, `space_reclaim`) the UI hides the option, yet `set_worm_lock` turns the lock on and answers success. From then on scheduled snapshots for that share are not taken and nothing is logged. Turning the lock off (`set_worm_lock type=Share name=SHARE worm_lock_enable=false worm_lock_day=7`) makes the next scheduled run work again.
- `SYNO.DisasterRecovery.Retention get_worm_lock` v1 `name=SHARE type=Share`: `worm_lock_enable`, `worm_lock_day`.
- Schedule: `SYNO.Core.Share.Snapshot get_schedule` v1 `name=SHARE` returns `enable_snapshot_schedule`, `schedule` and `task_id` (-1 when no schedule exists; a never-scheduled share and a disabled one can look alike). `set_schedule` v1 `name`, `enable_snapshot_schedule`, `schedule={"date": "YYYY/MM/DD", "date_type": 0, "week_name": "0,1,2,3,4,5,6", "hour": H, "min": M, "repeat": 0, "repeat_hour": 0, "repeat_min": 0, "last_work_hour": H, "monthly_week": []}`, `task_id` (-1 creates, the existing id updates). Do not send back `next_trigger_time` or the `*_store_config` fields from `get_schedule`.
- Retention: `SYNO.DisasterRecovery.Retention get` v1 `name=SHARE`; `set` v1 with `name`, `type=Share` and the fields `get` returned, `policyType=64` = keep by days, `retainDay=N`.
- Scheduled snapshots run as Task Scheduler tasks (owner root); `SYNO.Core.TaskScheduler run` v2 on that task id takes one now.
- `SYNO.Core.Share.Snapshot list` v2 `name=SHARE additional=["schedule_snapshot"]`: scheduled ones have `schedule_snapshot: true`; names are the NAS's local time, `GMT+01-2026.10.30-03.30.01`.

## Packages

- `SYNO.Core.Package list` (`additional=["status","installed_info","startable","dsm_apps","install_type"]`). `SYNO.Core.Package.Control start|stop id=...`. System packages (`startable=false`, e.g. SMBService, QuickConnect, SecureSignIn, StorageManager, FileStation) cannot be stopped.
- Install from Package Center: `SYNO.Core.Package.Installation install` (`name`, `volume_path`, `blqinst`, `is_syno`, `installrunpackage`), poll `status task_id=@SYNOPKG_DOWNLOAD_<id>`.
- Uninstall: `SYNO.Core.Package get id=X additional=["uninstall_pages"]` shows the wizard's checkboxes (e.g. "also delete images and containers"); `SYNO.Core.Package.Uninstallation uninstall` with `id`, `dsm_apps` and, for packages with a wizard, `extra_values` as a JSON string containing a JSON object (`"{\"key\":true}"`).
- Default install volume: `SYNO.Core.Package.Setting.Volume get|set default_vol=/volumeN`.

## DSM upgrade

- Newest build for a model: `https://www.synology.com/api/support/findDownloadInfo?lang=en-global&product=<model>&major=7&minor=N` (`pubVers`, then the `.pat` URL under `system.detail[].items[].files[]`).
- `SYNO.Core.Upgrade.Patch upload` v1: multipart, with `api`, `method`, `version`, `target=active` **before** the `file` part. `SYNO.Core.Upgrade.PreCheck start` v1 `type=patch`: code 5223 with `can_continue=true` is the normal "read the notes" answer. `SYNO.Core.Upgrade start` v1 `force=true type=patch` installs and reboots. `SYNO.Core.Upgrade.Patch clean` removes an uploaded patch.

## Notifications

- DSM webhook: `SYNO.Core.Notification.Push.Webhook.Provider create|set` v2 with `type=custom`, `url`, `req_method=post`, `req_header` = `Name:value\r` lines joined, `req_param` = the body template as a JSON string (`"{\"text\": \"@@TEXT@@\"}"`; a JSON object gives 4681), `template_id` (from `SYNO.Core.Notification.Advance.FilterSettings.Template list`, e.g. the built-in "Warning"), `provider`, `prefix`, `sepchar`, `needssl`, `port`, `interval`, `use_default_lang`. `list`, `send_test profile_id=N`.

## Other quirks

- `SYNO.Core.System.Utilization`: load averages are multiplied by 100 (13 means 0.13).
- File Station search (`SYNO.FileStation.Search start`): a comma-separated pattern list returns 0 hits; start one task per pattern. Only shares the signed-in account can see are searched.
- `SYNO.Storage.CGI.Smart.Scheduler set`: `id` inside `basic`/`app` must be the string `"-1"` (a number makes DSM answer HTTP 502); the schedule uses the old format `{date_type: 0, week_name: "0", hour: 3, min: 0, ...}`.
- `SYNO.Core.Storage.Disk deactivate_disk` (needs a `PasswordConfirm` token) answered success and did nothing for a disk outside the system RAID.
- `SYNO.Storage.CGI.Volume set_setting` (atime): send `desc` and `capacity_warn_percent` back unchanged with `atime_opt`, or they reset.
- A NAS that dials PPPoE itself uses it as the default gateway. Before disabling PPPoE set a gateway and DNS on the LAN interface, or the NAS loses internet access (updates, Cloud Sync).
- Cloud Sync: one connection per cloud account (a second answers 417); remote paths of tasks in one connection cannot overlap (424); an exclusion list means "everything not excluded syncs", including folders created later.
- Container Manager projects: `SYNO.Docker.Project list`, then `stop_stream`, `update` (content), `build_stream` with the project id. Containers on the bridge network do not get UDP replies some P2P protocols need; `network_mode: host` does.
- Tailscale package UI: `/webman/3rdparty/Tailscale/index.cgi/api/data` with the DSM session cookie (`id=<sid>`) returns status plus an `X-Csrf-Token` header and `_gorilla_csrf` cookie; `POST /api/up` with both and `{"Reauthenticate": true}` returns a login URL within seconds (`false` hangs). Node keys expire after 180 days unless key expiry is disabled in the Tailscale admin console. Outbound connections from the NAS into the tailnet need `tailscale configure-host` (root).
