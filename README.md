# synology-nas-cli

**Audit a Synology NAS against the C3RB3R / `.L0CK3D` ransomware campaign with one command, fix what it finds with a second, and keep running DSM from the terminal afterwards.**

`nas` is a small Python CLI (standard library only, Python 3.8+, so it also runs on DSM itself) for the DSM 7 Web API: status, health, logs, packages, volumes, Tailscale, DSM upgrades, scheduled health alerts pushed to a webhook, and an incident command written during the 2026 C3RB3R campaign against internet-exposed Synology NAS (Synology-SA-26:13, SA-26:14).

Not affiliated with Synology Inc. "Synology", "DSM" and "QuickConnect" are trademarks of Synology Inc.

- [What `nas incident` checks](#what-nas-incident-checks)
- [Install](#install)
- [Pick your setup](#pick-your-setup)
- [Configuration](#configuration)
- [Credentials](#credentials)
- [Backends](#backends)
- [Incident quick start](#incident-quick-start)
- [`nas incident fix`](#nas-incident-fix)
- [Other commands](#other-commands)
- [Alerts and webhooks](#alerts-and-webhooks)
- [Safety notes](#safety-notes)
- [Tests](#tests)
- [繁體中文說明](#繁體中文說明)

For AI agents: [`docs/MCP.md`](docs/MCP.md) (`nas mcp`), [`docs/EXIT-CODES.md`](docs/EXIT-CODES.md), [`schemas/`](schemas/) (JSON Schemas of `--json` output), [`llms.txt`](llms.txt), `skills/install.sh` / `skills/install.ps1` (install the skills into `~/.claude/skills`, `~/.cursor/skills`, `~/.codex/skills`, `~/.agents/skills`, `~/.grok/skills`, `~/.gemini/skills`, `~/.config/opencode/skills`, `~/.hermes/shared-skills` where present; `--copy`, `--dry-run`, `--uninstall`).

Further reading: [`docs/INCIDENT-C3RB3R.md`](docs/INCIDENT-C3RB3R.md) (the campaign and a response checklist), [`docs/ALERTS.md`](docs/ALERTS.md) (alert codes, webhook body, deployment paths), [`docs/DSM-API-NOTES.md`](docs/DSM-API-NOTES.md) (DSM Web API behaviour this tool relies on), and the agent skills in [`skills/`](skills/).

## What `nas incident` checks

Read-only. Each item prints `PASS`, `WARN`, `FAIL` or `SKIP` with a one-line hint. `--json` gives the same as JSON. Exit status 1 when any item is `FAIL`.

| Item | FAIL / WARN when | Fixable by `incident fix` |
|---|---|---|
| `dsm_version` | the DSM build is older than the SA-26:13 fixed build for its branch, or the branch (DSM 7.1 and older) gets no fix | `--upgrade` |
| `sa_26_14_packages` | Calendar, MailStation or PHP 7.3-8.4 below the fixed version: FAIL if running, WARN if stopped | stops running ones |
| `firewall` | firewall off (FAIL when the NAS holds a public address itself, e.g. dials PPPoE), or on with interfaces that accept unmatched traffic / rules that allow any source | yes |
| `quickconnect` | QuickConnect or its automatic router port forwarding is on | yes |
| `router_port_forwarding` | DSM keeps enabled UPnP/NAT-PMP port-forwarding rules on the router | yes |
| `public_ports` | DSM (or other service) ports answer on the public address. Only with `--probe` (opens TCP connections) | via firewall |
| `external_signins` | successful sign-ins from addresses outside `allowed_networks` in the connection log | no (investigate) |
| `failed_signins` | more than `--failed-threshold` (20) failed sign-ins in the last `--hours` (24) | via firewall |
| `autoblock` | AutoBlock off | yes |
| `smb_min_protocol` | SMB1 allowed (FAIL when SMB is on) | yes |
| `admin_account` | the built-in `admin` account is enabled | yes |
| `snapshot_schedule:<share>` | no snapshot schedule, schedule off, or no scheduled snapshot within `snapshot_max_age_hours` | creates a schedule where none exists (after a clean `--ransom-scan`) |
| `snapshot_worm:<share>` | immutable-snapshot (WORM) lock on, on a model that does not support it: DSM accepts the setting and scheduled snapshots then silently stop | yes |
| `ransomware_files` | `*.L0CK3D`, `*.LOCK3D` or `read-me3.txt` found in any share. Only with `--scan` (File Station search, minutes) | no (incident) |
| `exploit_attempts` | the connection log contains the CVE-2024-10441 sign-in injection (`PLUGIN_VALUE_END`, `LD_PRELOAD=`, `LD_DEBUG_OUTPUT`) or entries from `incident.ioc_ips` (WARN: attempt seen) | no |
| `exploit_attempts_logs`, `ioc_cron`, `ioc_binaries`, `ioc_users`, `ioc_ssh_keys`, `ioc_processes` | only with `--deep` (one read-only root script): injection blocks in `/var/log/synoplugin`, `synoscgi`, `auth` logs; planted cron files and download-and-run lines; known C3RB3R files; extra uid-0 or unknown accounts; `authorized_keys`; processes from temp folders or outside Synology paths, connections to IOC addresses. Details in [`docs/INCIDENT-C3RB3R.md`](docs/INCIDENT-C3RB3R.md#indicators-of-compromise-and-how-nas-incident---deep-checks-them) | no (incident) |

`SKIP` always says why: the item needs a flag (`--probe`, `--scan`), the API answered with an error, or the box does not have the feature (no Btrfs/Snapshot Replication, no router configured in DSM).

## Install

```bash
git clone <this repository> synology-nas-cli
cd synology-nas-cli
./bin/nas --help                     # runs from the checkout, nothing to install
ln -s "$PWD/bin/nas" ~/bin/nas       # optional: put it on PATH
```

or as a package with a `nas` console script:

```bash
pip install -e .                     # or: pipx install .
nas --help
```

Then create a config and check the login:

```bash
nas config init                      # writes ~/.config/synology-nas-cli/config.json (mode 600)
$EDITOR ~/.config/synology-nas-cli/config.json
nas config show                      # effective config, commands masked
nas whoami                           # one login: account, admin flag, DSM version, credential source
```

## Pick your setup

| Setup | Backend | Password from | Notes |
|---|---|---|---|
| macOS with 1Password | `password` | `op://VAULT/ITEM/password` refs; `op` signed in through the 1Password app | Approve `op` in the app the first time. 2FA codes from the same item (`op item get --otp`). |
| macOS without 1Password | `password` | `nas login --save` (Keychain), or `password_command` = `security find-generic-password -s synology-nas -a USER -w` | `nas login` also caches the session so later commands do not sign in again. |
| Linux server, cron, systemd timer | `password` | 1Password service account (`OP_SERVICE_ACCOUNT_TOKEN` or the token file) + `op://` refs, or `password_command` (`secret-tool lookup ...`, `pass show ...`) | No terminal: the prompt is off, so configure a non-interactive source. |
| Windows | `password` | `password_command` with PowerShell (see [Credentials](#credentials)), or `NAS_USER` + `NAS_PASSWORD` | `cmdkey` can store a credential but cannot print it back; use the CredentialManager PowerShell module. The keychain store is not available on Windows. |
| On the NAS itself | `local` | none: runs as root through DSM Task Scheduler | `nas alert-deploy` sets this up. Uses DSM's own Python 3.8. |
| CI / headless with a service account | `password` | `OP_SERVICE_ACCOUNT_TOKEN` (CI secret) + `op://` refs | Or `NAS_PASSWORD_COMMAND` reading the CI secret store. `NAS_PASSWORD` works but is the least safe. |

## Configuration

One JSON file: `$NAS_CONFIG`, else `~/.config/synology-nas-cli/config.json`. Every key is optional. Unknown keys are an error, so typos do not silently fall back to defaults. Keys beginning with `_` are comments. Environment variables override the file; command-line flags override both. `nas config show` prints the result with commands masked.

Example ([`config.example.json`](config.example.json), what `nas config init` writes; the addresses are documentation examples):

```json
{
  "name": "my-nas",
  "origins": ["https://192.0.2.10:5001", "https://my-nas.example-tailnet.ts.net:5001"],
  "lan_ip": "192.0.2.10",
  "snapshot_shares": ["photos", "documents"],
  "credentials": {
    "op_username": "op://VAULT/ITEM/username",
    "op_password": "op://VAULT/ITEM/password"
  },
  "webhook": {"file": "~/.config/synology-nas-cli/webhook.json"},
  "deploy": {"stage_dir": "/SHARE/.nas-cli-deploy"}
}
```

| Key | Default | Meaning |
|---|---|---|
| `name` | `nas` | Label in webhook bodies and the DSM notification prefix (`[name]`). |
| `origins` | `[]` | DSM URLs for `--backend password`, tried in order; the first that accepts a TCP connection (3 s) is used. Put the LAN address first, then a VPN/Tailscale one. |
| `chrome_origins` | = `origins` | Which Chrome tab `--backend chrome` may use. |
| `connect_timeout` | `3.0` | Seconds for the TCP reachability check. |
| `tls.verify` | `false` | `true`: check DSM's certificate against the system CAs (a real certificate for the origin's name). `false` (DSM ships a self-signed certificate): trust on first use, see [TLS](#tls). |
| `tls.known_certs_file` | `~/.config/synology-nas-cli/known-certs.json` | SHA-256 of the certificate each origin presented first (mode 600). `nas trust` lists it, `nas trust --reset ORIGIN` forgets one. |
| `lan_ip` / `public_ip` | `""` | Targets for `exposure` and `incident --probe`. `lan_ip` defaults to the host of the first origin. `public_ip` is only needed when the NAS does not dial PPPoE itself (behind a router: the router's WAN address). |
| `allowed_networks` | `[]` | Sign-ins from these are expected (`alert`, `incident`); empty = every non-global address (RFC 1918, 100.64.0.0/10, loopback, link-local, IPv6 ULA). For `incident fix` these IPv4 networks plus this computer's address (as DSM logged it, `/32`) are what the firewall and AutoBlock allow; empty = this computer only. IPv6 entries are not written as firewall rules. |
| `snapshot_shares` | `[]` | Shares whose scheduled snapshots `alert` watches. `incident` checks every share when empty. |
| `snapshot_max_age_hours` | `26` | A scheduled snapshot older than this is "stale". |
| `latest_dsm` | `""` | Newest build you expect for this model (e.g. `7.4.1-90080`); empty skips the `dsm_behind` alert. |
| `credentials.*` | see [Credentials](#credentials) | `source`, `op_username`, `op_password`, `op_otp`, `op_token_file`, `username`, `password_command`, `otp_command`, `store`, `store_service`. |
| `session.cache_file` | `~/.cache/synology-nas-cli/session.json` | Where `nas login` caches the DSM session. Nothing is cached unless you run `nas login`. |
| `session.device_token_file` | `~/.config/synology-nas-cli/device-token.json` | Trusted-device token from a 2FA login with `--trust-device`. |
| `session.device_name`, `session.trust_device` | `synology-nas-cli`, `false` | Device name shown in DSM; ask for a device token on every 2FA login. |
| `alert.state_file` | `~/.local/state/synology-nas-cli/baseline.json` | Baseline between `alert` runs. |
| `alert.package_volume` | `""` | Report packages installed outside this volume (e.g. `/volume1`). |
| `alert.recordings` | off | `{"path": "/share/folder", "local_path": "", "folders": ["cam1"], "max_age_min": 10, "note": ""}`: warn when a folder stops receiving files (camera recordings and the like). Empty `folders` = off. |
| `webhook.*` | `""` | Where `alert-deploy` reads `{"url", "header"}`: `op_item` (`op://VAULT/ITEM`: website = URL, field `op_header_field` = header), `file` (JSON file), or `command` (prints that JSON). |
| `deploy.*` | see `nas config show` | `root_dir` (`/volume1/@nas-alert`), `stage_dir` (a folder in a writable share), `task_name`, `install_task_name`, `interval_min` (10), `dsm_webhook_name`, `dsm_webhook_prefix`, `dsm_webhook_template` (`Warning`). |
| `upgrade.lang`, `upgrade.cache_dir` | `enu`, `~/.cache/synology-nas-cli/pat` | PreCheck note language; where `.pat` files are kept. |
| `incident.*` | `14`, `3`, `30`, `10`, `5`, `false` | `snapshot_retain_days` (only set on shares that have no retention policy), `snapshot_hour`, `snapshot_minute` for schedules `incident fix` creates; `autoblock_attempts`, `autoblock_within_mins` it sets; `ioc_ips` (default `46.8.78.122`, `104.253.175.125`), `ioc_strings` (extra strings) for `exploit_attempts` and `--deep`; `allowed_users` (accounts `--deep` treats as known); `autoblock_allow_loopback`: also allow-list `127.0.0.1` in AutoBlock (Tailscale's DSM package in userspace mode delivers every tailnet connection as `127.0.0.1`, so one blocked tailnet device would block all of them). |

Environment variables: `NAS_CONFIG`, `NAS_BACKEND`, `NAS_ORIGINS` (comma-separated; older name `NAS_LAN_ORIGIN`), `NAS_CHROME_ORIGINS` (older `NAS_ORIGIN`), `NAS_OP_ITEM` (`op://VAULT/ITEM`), `NAS_OP_TOKEN_FILE`, `NAS_USER`, `NAS_PASSWORD_COMMAND`, `NAS_PASSWORD`, `NAS_OTP_COMMAND`, `NAS_CREDENTIAL_SOURCE`, `NAS_SESSION_FILE`, `NAS_SID` + `NAS_SYNOTOKEN`, `OP_SERVICE_ACCOUNT_TOKEN`.

## Credentials

The password comes from the first configured source in this chain (`credentials.source` or `NAS_CREDENTIAL_SOURCE` can force one: `op`, `command`, `keychain`, `env`, `prompt`):

1. **1Password** (`op`): `credentials.op_password` = `op://VAULT/ITEM/FIELD` (and `op_username`, or a literal `username`). `op` authenticates with `OP_SERVICE_ACCOUNT_TOKEN`; if that is unset and `credentials.op_token_file` (default `~/.config/op/service-account-token`) exists, its content is used as the token; otherwise `op` uses its own sign-in (1Password app integration or `op signin`). `op` is only run when an `op://` reference is configured. `op read` fails on item names with non-ASCII characters: use the item ID.
2. **Command** (`command`): `NAS_PASSWORD_COMMAND`, else `credentials.password_command`, run with `/bin/sh -c` (`cmd.exe` on Windows); the first line of output is the password. Examples:
   - macOS Keychain: `security find-generic-password -s synology-nas -a USER -w`
   - Linux Secret Service: `secret-tool lookup service synology-nas account USER`
   - pass: `pass show nas/USER`
   - Bitwarden CLI: `bw get password synology-nas` (needs `BW_SESSION` from `bw unlock`)
   - Windows: `powershell -NoProfile -Command "(Get-StoredCredential -Target synology-nas).GetNetworkCredential().Password"` with the CredentialManager module (`Install-Module CredentialManager`). `cmdkey /generic:synology-nas /user:USER /pass` stores a credential but has no way to print the password again.
3. **OS keychain** (`keychain`): the entry `nas login --save` wrote. macOS Keychain through `security` (the password goes through `security -i` on stdin, not the command line) or the Linux Secret Service through `secret-tool` (password on stdin). `credentials.store` = `auto` (default), `keychain`, `secret-tool`, or `""` (off); service name `credentials.store_service`. `nas logout --forget` deletes it.
4. **Environment** (`env`): `NAS_USER` + `NAS_PASSWORD`. The least safe option: any process that can read the environment (and `ps e` on some systems) sees it.
5. **Prompt** (`prompt`): `getpass`, only when stdin is a terminal and nothing above is configured.

The username comes from `NAS_USER` / `credentials.username`, else `op_username`, else the keychain entry's account, else a prompt.

**2-step verification.** When DSM answers 403 the login is retried once with a code from `credentials.otp_command` / `NAS_OTP_COMMAND` (e.g. `oathtool --totp -b SECRET`), else `op item get --otp` when the password came from 1Password (add the DSM 2FA secret to the item as a one-time password), else a prompt. `nas login --trust-device` (or `session.trust_device: true`) asks DSM for a trusted-device token and stores it (mode 600); later logins send it and skip the code until DSM forgets the device.

**Sessions.** By default every command signs in and out (each sign-in adds a "signed in successfully" line to DSM's connection log). `nas login` signs in once and caches the SID and SynoToken in `session.cache_file` (mode 600); later commands reuse it, and when DSM rejects it (106 timeout, 107 duplicate login, 119 invalid SID) they sign in again and rewrite the cache. `nas logout` ends and deletes it. `NAS_SID` + `NAS_SYNOTOKEN` reuse a session you already have (for example copied from a browser): nothing signs in or out, and a rejected session is an error.

### TLS

The `password` backend never uses `HTTP(S)_PROXY`, `ALL_PROXY` or the system proxy settings for DSM. With `tls.verify: false` (default) the SHA-256 of the certificate an origin presents on the first connection is stored in `tls.known_certs_file` (mode 600; `nas: trusting the certificate of ... on first use` on stderr) and every later connection must present the same certificate, otherwise the command stops with `the TLS certificate of ORIGIN changed`. After replacing the DSM certificate: `nas trust --reset https://HOST:PORT`. `nas trust` lists the stored fingerprints. With `tls.verify: true` the system CAs decide and nothing is pinned. A warning is printed when the 1Password token file is readable by other users.

**AutoBlock.** DSM blocks an address after 10 failed sign-ins within 5 minutes by default, often permanently. `nas` never retries a failed password. A wrong password in your source costs one attempt per command, so fix the source before running again. Code 407 means the address is already blocked: remove it from Control Panel > Security > Protection > Allow/Block List from another address.

## Backends

| Backend | When | How it signs in | Limits |
|---|---|---|---|
| `password` (default) | From any computer that reaches DSM over HTTPS (LAN, VPN, Tailscale) | The credential chain above | Needs an origin in the config. |
| `chrome` | macOS only, when you are already signed in to DSM in Google Chrome and do not want to store a password anywhere | Runs same-origin requests inside the DSM tab via AppleScript (Chrome: View > Developer > Allow JavaScript from Apple Events) | No uploads (`upgrade`, `alert-deploy`), no package web UIs (`tailscale`). |
| `local` | On the NAS itself as root (DSM Task Scheduler), e.g. what `alert-deploy` installs | None: `/usr/syno/bin/synowebapi --exec` runs the API as the system | Only on the NAS, only as root. Tailscale status via the `tailscale` binary. |

## Incident quick start

```bash
nas incident                       # read-only audit
nas incident --probe               # also test the public address from this machine
nas incident --scan                # also search every share for ransom notes (minutes)
nas incident --deep                # also indicators of compromise via one read-only root script (needs deploy.stage_dir)
nas --json incident                # machine-readable

nas incident fix --dry-run         # the plan: every change (current -> new), the API calls, the DSM UI path
nas incident fix                   # same plan, asks before applying
nas incident fix --yes             # apply without asking
nas incident fix --only firewall,smb_min_protocol
nas incident fix --skip admin_account
nas incident fix --ransom-scan --yes          # a clean scan also allows the snapshot fixes
nas incident fix --upgrade --rotate-password --yes   # opt-in extras
```

If the audit shows `ransomware_files FAIL` or `external_signins FAIL` you are past hardening: follow [`docs/INCIDENT-C3RB3R.md`](docs/INCIDENT-C3RB3R.md) (isolate first, keep evidence, restore from snapshots).

## `nas incident fix`

Runs the audit, prints the plan, asks (unless `--yes`; without a terminal it does not apply anything without `--yes`), applies the changes in this order, reads each one back, then runs the audit again and prints before -> after. `--dry-run` prints the plan and the exact calls and sends no write. Exit status 1 when a change fails or the final audit still has a FAIL.

Order: `snapshot_worm` -> `snapshots` -> `packages` -> `smb_min_protocol` -> `quickconnect` -> `router_port_forwarding` -> `autoblock` -> `admin_account` -> `firewall` -> `rotate_password` (opt-in) -> `upgrade` (opt-in, reboots).

| Fix | What changes | DSM web UI (manual way) | Raw call (`nas api ... --allow-write`) |
|---|---|---|---|
| `snapshot_worm` | Immutable-snapshot lock off on shares where the model lacks immutable snapshots (gated like `snapshots`: the share's schedule starts taking snapshots again) | Snapshot Replication > Snapshots > Settings (the option is hidden on unsupported models, so the API is the only way) / Snapshot Replication > 快照 > 設定 | `SYNO.DisasterRecovery.Retention set_worm_lock --version 1 type=Share name=SHARE worm_lock_enable=false worm_lock_day=7` |
| `snapshots` | Create a daily schedule (`incident.snapshot_hour:minute`) on shares that have none, with retention by days (`incident.snapshot_retain_days`, 14) only where the share has no retention policy yet. Existing schedules, enabled or not, and existing retention are left alone. Refused unless the same run's `--ransom-scan` came back clean or `--i-know-snapshots-may-rotate` is given: snapshots that start being taken apply retention, which can delete the older snapshots needed to recover encrypted files | Snapshot Replication > Snapshots > select the share > Settings > Schedule / Retention Policy (Snapshot Replication > 快照 > 設定 > 排程 / 保留原則) | `SYNO.Core.Share.Snapshot set_schedule --version 1 name=SHARE enable_snapshot_schedule=true 'schedule={...}' task_id=-1` then `SYNO.DisasterRecovery.Retention set --version 1 name=SHARE type=Share policyType=64 retainDay=14 ...` |
| `packages` | Stop running packages named in SA-26:14 (update or uninstall them yourself) | Package Center > Installed > package > Update or Stop (套件中心 > 已安裝) | `SYNO.Core.Package.Control stop --version 1 id=PHP7.4` |
| `smb_min_protocol` | Minimum SMB protocol SMB2 (SMB1-only clients lose access) | Control Panel > File Services > SMB > Advanced Settings (控制台 > 檔案服務 > SMB > 進階設定) | `SYNO.Core.FileServ.SMB set --version 3 smb_min_protocol=1 smb_max_protocol=3` |
| `quickconnect` | QuickConnect off, and its automatic router port forwarding off | Control Panel > External Access > QuickConnect (控制台 > 外部存取 > QuickConnect) | `SYNO.Core.QuickConnect set --version 2 enabled=false`; `SYNO.Core.QuickConnect.Upnp set --version 1 enabled=false` |
| `router_port_forwarding` | Disable (not delete) the router port-forwarding rules DSM manages over UPnP/NAT-PMP | Control Panel > External Access > Router Configuration (控制台 > 外部存取 > 路由器設定); also check the router's own page | `SYNO.Core.PortForwarding.Rules save --version 1 'rules=[...enable:false...]' task_id_suffix=PF`, poll `save_status` |
| `autoblock` | AutoBlock on (10 attempts / 5 min); allow-list this computer's address as DSM logged it, the IPv4 `allowed_networks`, and `127.0.0.1` only with `incident.autoblock_allow_loopback` | Control Panel > Security > Protection > Auto Block; Allow/Block List (控制台 > 安全性 > 保護) | `SYNO.Core.Security.AutoBlock set --version 1 enable=true attempts=10 within_mins=5 enable_expire=false expire_day=0`; `SYNO.Core.Security.AutoBlock.Rules create --version 1 type=allow block_days=0 overwrite=true 'ip=["127.0.0.1"]'` |
| `admin_account` | Disable the built-in `admin`. Refused when the CLI is signed in as `admin`, when the account of a pasted `NAS_SID` session cannot be resolved (`SYNO.Core.Desktop.Initdata`), or when no other enabled member of `administrators` exists. `SYNO.Core.User set` answers 105 from a password session, so it runs as root in a temporary Task Scheduler task that is deleted afterwards | Control Panel > User & Group > admin > Edit > Disable this account (控制台 > 使用者與群組) | root task script: `/usr/syno/bin/synowebapi --exec api=SYNO.Core.User method=set version=1 name='"admin"' expired='"now"'` (with `--backend local`: `SYNO.Core.User set --version 1 name=admin expired=now`) |
| `firewall` | Enable the firewall; allow rules (this computer's `/32` as DSM logged it + IPv4 `allowed_networks`) on the LAN interfaces (`global` only when the profile has no LAN interface); every interface except `global` (eth*, pppoe, ppp0, vpn, wlan0, ...) drops unmatched traffic; rules that allow any source are removed | Control Panel > Security > Firewall > Edit Rules (控制台 > 安全性 > 防火牆 > 編輯規則) | `SYNO.Core.Security.Firewall.Profile set --version 1 'profile={...}' profile_applying=false`, then `SYNO.Core.Security.Firewall.Profile.Apply start --version 1 name=default profile_applying=false`, poll `status task_id=...`, `stop` |
| `rotate_password` (`--rotate-password`) | New random 24-character password for the signed-in account. Written to the store first (1Password item via `op item edit` on stdin, keeping the old value in the item history; or the keychain entry, with the old value copied to `<store_service>-previous`), then changed in DSM; if DSM refuses, the old password goes back into the store; if the DSM call is interrupted the store keeps the new one. Read back and a fresh login verified. Never printed. Refused when the password comes from a command, env or prompt | Personal > Account > change password (個人 > 帳號) | `SYNO.Core.NormalUser set --version 2 password=... old_password=...` |
| `upgrade` (`--upgrade`) | Download the newest official `.pat`, upload, PreCheck, install; the NAS reboots | Control Panel > Update & Restore > Manual DSM Update (控制台 > 更新與還原) | `nas upgrade --yes` |

**Firewall lockout guard.** The firewall change is refused when: HTTP(S) proxies are configured for the origin; the origin is a loopback address (SSH tunnel, local proxy) or a public address; the newest successful sign-in of this account in DSM's connection log shows a loopback, IPv6 or public source; or that logged source differs from the local address this computer uses to reach the NAS (NAT, a proxy, or the sign-in came from another device). The allowed set always contains the address DSM logged. After applying, it signs in again over the same origin from scratch; if that fails it prints rescue steps: another computer on the LAN, Synology Assistant / find.synology.com, Tailscale userspace mode (DSM sees `127.0.0.1`, which the firewall did not filter in testing), and the RESET button (mode 1). IPv6 allow-list entries are not written as rules, so IPv6 sources are dropped. `100.64.0.0/10` (Tailscale) is also the range CGNAT ISPs use on the WAN side: on a NAS that dials PPPoE itself, a `global` allow rule for it would admit other subscribers, which is why the rules go on the LAN interfaces.

**A NAS with its own public address** (it dials PPPoE itself, or sits in a DMZ) has no router NAT in front of it: the DSM firewall is then the only layer between every DSM service and the internet. QuickConnect and UPnP port forwarding open DSM to the internet even behind NAT.

## Other commands

```bash
nas whoami        # backend, origin, credential source, session, account, admin flag, DSM version
nas status        # model, DSM version, uptime, SA-26:13 verdict
nas net           # interfaces, PPPoE (public address), firewall, gateway
nas services      # SSH / FTP / SMB / AFP / NFS / rsync / QuickConnect / AutoBlock / DSM ports
nas inventory     # shares, packages (SA-26:14 flags), containers, users (2FA), scheduled tasks
nas health        # disks (SMART, temperature), pools, volumes, UPS, CPU, memory
nas logs --since "2026-10-30 00:00" --top 5   # failed sign-ins by user/IP, external successes
nas ransom-scan   # File Station search for *.L0CK3D, *.LOCK3D, read-me3.txt (one task per pattern)
nas exposure      # TCP probe of LAN and public addresses from this machine
nas upgrade --dry-run | nas upgrade | nas upgrade --yes | nas upgrade --wait-only
nas pkg list | start ID | stop ID | install ID [--volume /volume1] | uninstall ID [--remove-data] | default-volume [/volumeN]
nas volume list | volume atime volume_1 noatime
nas tailscale status | tailscale login-url [--force]
nas alert [--no-update] [--push webhook.json]
nas alert-deploy [--test] [--interval 10] [--webhook-item op://VAULT/ITEM] [--no-dsm-webhook]
nas login [--save] [--trust-device] [--no-cache] | nas logout [--forget]
nas config init [--force] | nas config show
nas trust | nas trust --reset https://HOST:PORT                # TLS certificates trusted on first use
nas api SYNO.Core.System info --version 1                     # any DSM API; writes need --allow-write
nas --json <command>                                          # JSON output for everything
nas --no-input <command>                                      # never prompt; exit 3 when input would be needed (also NAS_NO_INPUT=1; automatic without a terminal)
nas mcp                                                       # MCP server on stdio (docs/MCP.md)
```

## Alerts and webhooks

`nas alert` runs every health and security check once and exits 1 when something is at warning/critical level. Every finding is `{level, code, kind, message}`. With `--push FILE` it POSTs only what changed since the last successful push to `{"url", "header"}` from FILE: new conditions, a reminder every 24 h for warning/critical ones still present, every event, resolved keys, and one heartbeat a day. Codes, the body format and receiver examples are in [`docs/ALERTS.md`](docs/ALERTS.md).

Three ways to run it:

1. **On the NAS, set up for you:** `nas alert-deploy` copies the code into a root-only folder (`deploy.root_dir`), creates a root Task Scheduler task running `nas --backend local alert --push` every 10 minutes, and points DSM's own notification webhook (Control Panel > Notification > Webhooks) at the same URL.
2. **On the NAS, by hand:** the same three pieces done in DSM's UI. Steps in [`docs/ALERTS.md`](docs/ALERTS.md#manual-install-on-the-nas).
3. **From another always-on machine:** cron or launchd running `nas alert --push ...` with the `password` backend. See [`docs/ALERTS.md`](docs/ALERTS.md#from-another-machine-cron--launchd).

Receivers: any HTTPS endpoint that takes a JSON POST with one header (generic JSON receiver), a chat-bot "routine" webhook that starts an agent run per POST (Grok-Bot-style), or no webhook at all: DSM's built-in notifications (email, Synology mobile push through the DS finder / Synology app) cover DSM's own warning/error events. All three are in [`docs/ALERTS.md`](docs/ALERTS.md#receivers).

## Safety notes

- Every command is read-only except: `incident fix` (asks, or `--yes`), `upgrade` (without `--yes` it still uploads the `.pat` and runs PreCheck, then deletes the upload; `--yes` installs), `pkg start|stop|install|uninstall|default-volume VOL`, `volume atime`, `tailscale login-url`, `alert-deploy`, `login --save` / `logout --forget` (local keychain only), `trust --reset` (local file), and `api` with `--allow-write`. `ransom-scan`, `incident --scan` and `incident fix --ransom-scan` create temporary File Station search tasks on the NAS (stopped and cleaned afterwards). `nas api` refuses methods that do not look like reads unless `--allow-write` is given.
- `incident fix --dry-run` prints every write call it would send. The plan always shows current -> new values.
- Passwords, SIDs and SynoTokens are never printed. `nas api` prints raw DSM output, which can include serial numbers and account names; the other commands filter those.
- Each password sign-in that fails counts toward AutoBlock. The CLI never retries a failed password.
- `alert-deploy` installs code that runs as root on the NAS; the code lives outside the shared folders so share users cannot change it.

## Tests

```bash
tests/run_offline.sh      # all offline tests with python3, and with Python 3.8 when `uv python find 3.8` works
tests/smoke_live.sh       # optional: read-only commands against your NAS (uses your config)
```

## 繁體中文說明

**一個指令檢查 Synology NAS 有沒有被 C3RB3R／`.L0CK3D` 勒索潮打中的弱點，再一個指令把找到的問題修好；平常也能在終端機管理 DSM。**

- 只用 Python 標準函式庫（3.8 以上），在 DSM 上也能直接跑。本專案與 Synology 無關。
- 安裝：`git clone` 之後直接跑 `bin/nas`，或 `pip install -e .`。`nas config init` 產生設定檔（`~/.config/synology-nas-cli/config.json`），填上 DSM 網址和帳密來源，`nas whoami` 確認能登入。
- 帳密來源依序：1Password（`op://` 參照，service account token 或已登入的 1Password App）→ `NAS_PASSWORD_COMMAND`（任何印出密碼的指令，例如 macOS 鑰匙圈、`secret-tool`、`pass`、Bitwarden）→ `nas login --save` 存進系統鑰匙圈 → `NAS_USER` + `NAS_PASSWORD`（最不安全）→ 在終端機互動輸入。兩步驟驗證碼可來自 `otp_command`、1Password 或互動輸入；`nas login --trust-device` 讓 DSM 記住這台裝置。
- `nas incident`：唯讀檢查 DSM 版本（SA-26:13）、SA-26:14 套件、防火牆、QuickConnect、路由器連接埠轉送、公網連接埠（`--probe`）、外部登入成功紀錄、登入失敗次數、自動封鎖、SMB1、內建 admin、各共用資料夾的排程快照，以及不支援卻開了不可變快照（WORM）導致排程快照靜靜停掉的陷阱、勒索檔案（`--scan`）。每項 PASS／WARN／FAIL／SKIP，有 FAIL 時結束碼 1。
- `nas incident fix`：先列出計畫（每項變更的現值→新值、實際送出的 API、DSM 網頁上的對應位置），確認後依序套用並逐項讀回驗證，最後重跑檢查列出前後對照。`--dry-run` 只印計畫不送出任何寫入；`--only`／`--skip` 選項目；`--upgrade`、`--rotate-password`、`--ransom-scan` 要另外加。快照相關修復要先跑乾淨的 `--ransom-scan`（或加 `--i-know-snapshots-may-rotate`），因為開始排程快照會套用保留原則、可能刪掉還原需要的舊快照；只替沒有排程的共用資料夾建立排程，不改既有排程和保留原則。
- TLS：連 DSM 不經過任何 proxy；自簽憑證第一次連線時記下指紋，之後換憑證就拒絕連線（`nas trust --reset` 重新信任）。
- 防火牆保護：以 DSM 連線紀錄裡這次登入的來源位址為準，跟本機位址不一致、是 loopback／IPv6／公網位址、或設了 proxy 就拒絕套用；允許清單預設只有這台電腦（/32）加上 `allowed_networks`，規則放在區網介面上；套用後重新登入一次確認，失敗會印出救援步驟（區網其他電腦、Synology Assistant、Tailscale、RESET 鍵 mode 1）。NAS 自己撥 PPPoE 拿到公網 IP 時，前面沒有路由器 NAT，DSM 防火牆就是唯一一層。
- AutoBlock：預設 5 分鐘內失敗 10 次就封鎖來源 IP。這個工具登入失敗不會重試。
- 監控：`nas alert` 可推播到任何 HTTPS webhook；`nas alert-deploy` 把它裝到 NAS 上用 root 排程跑，也可以手動在 DSM 設定，或在另一台常開的電腦用 cron／launchd 跑。不想用 webhook 時，DSM 內建的 Email／手機推播通知也能收到 DSM 自己的警告。

## License

MIT, Copyright (c) 2026 Akari Sora. See [LICENSE](LICENSE).
