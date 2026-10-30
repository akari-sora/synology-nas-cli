# synology-nas-cli

**Audit a Synology NAS against the C3RB3R / `.L0CK3D` ransomware campaign with one command, fix what it finds with a second, and keep running DSM from the terminal afterwards.**

[![Releases](https://img.shields.io/badge/releases-GitLab-fc6d26)](https://gitlab.com/aa22396584/synology-nas-cli/-/releases) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Canonical repository, releases and issues: https://gitlab.com/aa22396584/synology-nas-cli

`nas` is a zero-dependency Python CLI (standard library only, Python 3.8+, so it also runs on DSM itself) and stdio MCP server for the Synology DSM 7 Web API: status, health, logs, packages, volumes, Tailscale, DSM upgrades, scheduled health alerts pushed to a webhook, and an incident audit and remediation tool built during the October 2026 C3RB3R / `.L0CK3D` campaign against internet-exposed Synology NAS boxes (Synology-SA-24:20, SA-26:13, SA-26:14).

Not affiliated with Synology Inc. "Synology", "DSM" and "QuickConnect" are trademarks of Synology Inc.

- [Hand it to your agent](#hand-it-to-your-agent)
- [What it checks and fixes](#what-it-checks-and-fixes)
- [Install](#install)
- [Pick your setup](#pick-your-setup)
- [Configuration](#configuration)
- [Credentials](#credentials)
- [Backends](#backends)
- [Incident quick start](#incident-quick-start)
- [`nas incident fix`](#nas-incident-fix)
- [MCP server and agent skills](#mcp-server-and-agent-skills)
- [Alerts and webhooks](#alerts-and-webhooks)
- [Command reference summary](#command-reference-summary)
- [What changes the NAS](#what-changes-the-nas)
- [Tests](#tests)
- [繁體中文說明](#繁體中文說明)

## Hand it to your agent

Paste either prompt into Claude Code, Codex, Cursor, Gemini CLI, OpenCode, Grok Bot, or any tool-using AI agent (Grok Bot setup, skills and alert routine: [`docs/GROK-BOT.md`](docs/GROK-BOT.md)):

**English prompt:**

```text
Use https://github.com/akari-sora/synology-nas-cli to audit and fix my Synology NAS at https://192.0.2.10:5001. Follow docs/AGENT-RUNBOOK.md.
```

**繁體中文提示詞：**

```text
使用 https://github.com/akari-sora/synology-nas-cli 檢查並修復我的 Synology NAS（位址：https://192.0.2.10:5001），照著 docs/AGENT-RUNBOOK.md 的步驟執行。
```

### What the agent does, step by step

1. **Install**: Clones the repository (or installs the package) and verifies `./bin/nas --version`.
2. **`nas setup`**: Runs `nas setup --json --no-input ...` to write `~/.config/synology-nas-cli/config.json` (mode `0600`), signs in once to verify credentials, and pins DSM's TLS certificate SHA-256 fingerprint on first use.
3. **`nas doctor`**: Runs `nas doctor --json` to verify configuration, credentials, origin reachability, TLS pin, login, DSM version against SA-26:13, 2-step verification status, administrator capabilities, and clock skew.
4. **`nas incident`**: Runs `nas incident --json` (and optionally `--probe --scan`) for a read-only audit of DSM version, vulnerable packages, firewall, QuickConnect, UPnP router rules, public ports, external and failed sign-ins, AutoBlock, SMB1, built-in `admin`, snapshot schedules, the unsupported-model WORM lock trap, ransom notes, and CVE-2024-10441 exploit attempts.
5. **Plan**: Runs `nas incident fix --dry-run --json --ransom-scan` and shows every planned change (`before -> after`), the exact DSM Web API calls, and the corresponding DSM web UI path.
6. **`nas incident fix --yes`**: Applies the approved plan in order (`snapshot_worm` → `snapshots` → `packages` → `smb_min_protocol` → `quickconnect` → `router_port_forwarding` → `autoblock` → `admin_account` → `firewall`, plus optional `--rotate-password` and `--upgrade`), reads every setting back to verify, and re-runs the audit.
7. **Optional `--deep` and `alert-deploy`**: Runs `nas incident --deep --json` (one read-only root collector via Task Scheduler checking root-only logs, crontabs, `/bin` binaries, accounts, SSH keys, and `/proc`) and `nas alert-deploy --json --test` (10-minute health and security monitoring pushed to a webhook).

### What you provide along the way

1. **NAS address and account (once)**:
   - DSM URL (for example `https://192.0.2.10:5001`, plus a VPN/Tailscale URL if used).
   - An administrator username and where its password comes from (`op://VAULT/ITEM/password`, a password command, or the OS keychain).
   - Your LAN/VPN subnet CIDR(s) to keep allowed in the firewall (for example `192.0.2.0/24`).
   - An optional shared folder path for temporary staging (for example `/docker/.nas-cli-deploy`, used by `--deep` and `alert-deploy`).
2. **A 6-digit 2FA code (once, if 2-step verification is on)**:
   - When `nas setup` exits `3` with `"field": "otp"`, provide the current 6-digit code; `--trust-device` stores DSM's trusted-device token (`0600`) so subsequent commands do not need a code.
3. **Plan confirmation**:
   - Review the dry-run plan before `nas incident fix --yes` runs (and choose whether to include `--rotate-password` or `--upgrade`).

Full agent specification: [`docs/AGENT-RUNBOOK.md`](docs/AGENT-RUNBOOK.md).

## What it checks and fixes

`nas incident` is read-only. Each item prints `PASS`, `WARN`, `FAIL` or `SKIP` with a one-line hint (`--json` outputs structured JSON; schema in [`schemas/incident.schema.json`](schemas/incident.schema.json)). Exit status is `1` when any item is `FAIL`.

| Item | What `nas incident` reports | What `nas incident fix` changes |
|---|---|---|
| `dsm_version` | `FAIL` if the DSM build is older than the SA-26:13 fixed build for its branch, or on a branch with no SA-26:13 fix (DSM 7.1 and older); `PASS` if patched | With `--upgrade`: downloads the newest official `.pat` for the model, runs PreCheck, installs, and reboots |
| `sa_26_14_packages` | Checks installed packages against Synology-SA-26:14 (Calendar, MailStation, PHP 7.3–8.4): `FAIL` if a vulnerable version is running, `WARN` if installed but stopped | Stops running vulnerable packages (`--only packages`) |
| `firewall` | `FAIL` when the firewall is off and the NAS holds a public IP itself (e.g. dials PPPoE), `WARN` when off behind NAT, or `FAIL`/`WARN` when interfaces accept unmatched traffic or rules allow any source (`source_ip: all`) | Enables the firewall, adds allow rules for this computer's `/32` (as DSM logged it) plus IPv4 `allowed_networks` on LAN interfaces, sets every non-`global` interface policy to `drop`, and removes allow-any-source rules (`--only firewall`) |
| `quickconnect` | `FAIL` when QuickConnect or QuickConnect automatic router port forwarding is enabled | Turns off QuickConnect and its UPnP router port forwarding (`--only quickconnect`) |
| `router_port_forwarding` | `FAIL` when DSM has enabled UPnP/NAT-PMP port-forwarding rules on the router | Disables all router port-forwarding rules managed by DSM (`--only router_port_forwarding`) |
| `public_ports` | Only with `--probe`: opens TCP connections from this machine to DSM and file-service ports on the NAS's public IP (`FAIL` if any port answers) | Covered by `firewall`, `quickconnect`, and `router_port_forwarding` |
| `external_signins` | `FAIL` when the connection log contains successful sign-ins from source addresses outside `allowed_networks` | None (investigate unauthorized access; see [`docs/INCIDENT-C3RB3R.md`](docs/INCIDENT-C3RB3R.md)) |
| `failed_signins` | `WARN` when failed sign-ins in the last `--hours` (default `24`) exceed `--failed-threshold` (default `20`) | Mitigated by `firewall` and `autoblock` |
| `autoblock` | `FAIL` when AutoBlock is disabled | Enables AutoBlock (`10` attempts within `5` minutes, permanent block) and allow-lists this computer's IP plus IPv4 `allowed_networks` (and `127.0.0.1` if `incident.autoblock_allow_loopback` is true) (`--only autoblock`) |
| `smb_min_protocol` | `FAIL` when SMB is enabled and allows SMB1 (`smb_min_protocol=0`), `WARN` when SMB is off but minimum protocol is SMB1 | Raises minimum SMB protocol to SMB2 (`smb_min_protocol=1`, `smb_max_protocol=3`) (`--only smb_min_protocol`) |
| `admin_account` | `FAIL` when the built-in `admin` account is enabled (`expired: normal`) | Disables the built-in `admin` account via a temporary root task after checking that another enabled administrator exists and the current session is not `admin` (`--only admin_account`) |
| `snapshot_schedule:<share>` | Per shared folder: `FAIL` if no snapshot schedule exists, the schedule is disabled, or the newest scheduled snapshot is older than `snapshot_max_age_hours` (default `26` h) | Creates a daily snapshot schedule (`03:30` default) and a 14-day retention policy on shares that have no schedule yet; gated on a clean `--ransom-scan` in the same run or `--i-know-snapshots-may-rotate` (`--only snapshots`) |
| `snapshot_worm:<share>` | `FAIL` when the immutable-snapshot (WORM) lock is enabled on a model whose `SYNO.DisasterRecovery.Retention info` lacks `worm` (DSM accepts the API call and scheduled snapshots silently stop) | Turns off the unsupported WORM lock on affected shares so scheduled snapshots resume; gated like `snapshots` (`--only snapshot_worm`) |
| `ransomware_files` | Only with `--scan`: searches shares via File Station for `*.L0CK3D`, `*.LOCK3D`, and `read-me3.txt` (`FAIL` if any match is found) | None (incident response required; see [`docs/INCIDENT-C3RB3R.md`](docs/INCIDENT-C3RB3R.md)) |
| `exploit_attempts` | Scans the DSM connection log for CVE-2024-10441 sign-in injection markers (`PLUGIN_VALUE_END`, `LD_PRELOAD=`, `LD_DEBUG_OUTPUT`) and `incident.ioc_ips` (`WARN` when attempts are seen) | None (check `--deep` to verify whether any attempt succeeded) |
| `exploit_attempts_logs`, `ioc_cron`, `ioc_binaries`, `ioc_users`, `ioc_ssh_keys`, `ioc_processes` | Only with `--deep`: runs one read-only root collector to inspect `/var/log/synoplugin.log*`, `/var/log/synoscgi.log*`, `/var/log/auth.log*`, crontabs (`/etc/cron.d/synot*`), `/bin/libgld`, `/bin/qnetd`, `/bin/l0ck.enc`, `xdy5*`, extra uid-0 or unknown accounts, `authorized_keys`, and `/proc` processes/connections (`FAIL` on known C3RB3R artifacts, `WARN` on unknown entries) | None (incident response required; see [`docs/INCIDENT-C3RB3R.md`](docs/INCIDENT-C3RB3R.md)) |

`SKIP` always states the reason: the item needs a flag (`--probe`, `--scan`), the API returned an error, or the NAS does not use that feature (no Btrfs/Snapshot Replication, no router configured in DSM).

## Install

### From a Git checkout (zero install)

```bash
git clone https://gitlab.com/aa22396584/synology-nas-cli.git synology-nas-cli
cd synology-nas-cli
./bin/nas --help                     # runs directly from the checkout (Python 3.8+ stdlib only)
ln -s "$PWD/bin/nas" ~/bin/nas       # optional: put `nas` on PATH
```

### With `pip` from a GitLab release or local checkout

```bash
pip install https://gitlab.com/aa22396584/synology-nas-cli/-/archive/v1.0.0/synology-nas-cli-v1.0.0.tar.gz
# or from a local checkout:
pip install -e .                     # or: pipx install .
nas --help
```

### On Windows (with `py`)

```powershell
git clone https://gitlab.com/aa22396584/synology-nas-cli.git synology-nas-cli
cd synology-nas-cli
py -3 bin\nas --help
# or install the console script:
py -3 -m pip install -e .
nas --help
```

### Initialize and verify login

Interactive or agent-driven one-step setup:

```bash
nas setup --origin https://192.0.2.10:5001 --user ops --password-source op:op://VAULT/ITEM/password --allowed-network 192.0.2.0/24
nas doctor
```

Or create the config file from the template and edit it by hand:

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
| Windows | `password` | `password_command` with PowerShell (see [Credentials](#credentials)), or `NAS_USER` + `NAS_PASSWORD` | Store the credential with the CredentialManager PowerShell module (`New-StoredCredential`) and read it with `Get-StoredCredential` in `password_command`. |
| On the NAS itself | `local` | none: runs as root through DSM Task Scheduler | `nas alert-deploy` sets this up. Uses DSM's own Python 3.8. |
| CI / headless with a service account | `password` | `OP_SERVICE_ACCOUNT_TOKEN` (CI secret) + `op://` refs | Or `NAS_PASSWORD_COMMAND` reading the CI secret store. `NAS_PASSWORD` also works. |

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
| `assume_yes` | `false` | Accept every confirmation (same as `--yes` / `NAS_YES=1`; what that turns on: [What changes the NAS](#what-changes-the-nas)). The MCP server does not read it. |
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
| `incident.*` | `14`, `3`, `30`, `10`, `5`, `false` | `snapshot_retain_days` (only set on shares that have no retention policy), `snapshot_hour`, `snapshot_minute` for schedules `incident fix` creates; `autoblock_attempts`, `autoblock_within_mins` it sets; `ioc_ips` (default `46.8.78.122` from public reports and `104.253.175.125`, observed in the wild on 2026-10-28), `ioc_strings` (extra strings) for `exploit_attempts` and `--deep`; `allowed_users` (accounts `--deep` treats as known); `autoblock_allow_loopback`: also allow-list `127.0.0.1` in AutoBlock (Tailscale's DSM package in userspace mode delivers every tailnet connection as `127.0.0.1`, so one blocked tailnet device would block all of them). |

Environment variables: `NAS_CONFIG`, `NAS_BACKEND`, `NAS_YES`, `NAS_NO_INPUT`, `NAS_ORIGINS` (comma-separated; older name `NAS_LAN_ORIGIN`), `NAS_CHROME_ORIGINS` (older `NAS_ORIGIN`), `NAS_OP_ITEM` (`op://VAULT/ITEM`), `NAS_OP_TOKEN_FILE`, `NAS_USER`, `NAS_PASSWORD_COMMAND`, `NAS_PASSWORD`, `NAS_OTP_COMMAND`, `NAS_CREDENTIAL_SOURCE`, `NAS_SESSION_FILE`, `NAS_SID` + `NAS_SYNOTOKEN`, `OP_SERVICE_ACCOUNT_TOKEN`.

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
4. **Environment** (`env`): `NAS_USER` + `NAS_PASSWORD`. The value sits in the process environment (readable by processes of the same user, and by `ps e` on some systems).
5. **Prompt** (`prompt`): `getpass`, only when stdin is a terminal and nothing above is configured.

The username comes from `NAS_USER` / `credentials.username`, else `op_username`, else the keychain entry's account, else a prompt.

**2-step verification.** When DSM answers 403 the login is retried once with a code from `credentials.otp_command` / `NAS_OTP_COMMAND` (e.g. `oathtool --totp -b SECRET`), else `op item get --otp` when the password came from 1Password (add the DSM 2FA secret to the item as a one-time password), else a prompt. `nas login --trust-device` (or `session.trust_device: true`) asks DSM for a trusted-device token and stores it (mode 600); later logins send it and skip the code until DSM forgets the device.

**Sessions.** By default every command signs in and out (each sign-in adds a "signed in successfully" line to DSM's connection log). `nas login` signs in once and caches the SID and SynoToken in `session.cache_file` (mode 600); later commands reuse it, and when DSM rejects it (106 timeout, 107 duplicate login, 119 invalid SID) they sign in again and rewrite the cache. `nas logout` ends and deletes it. `NAS_SID` + `NAS_SYNOTOKEN` reuse a session you already have (for example copied from a browser): nothing signs in or out, and a rejected session is an error.

### TLS

The `password` backend never uses `HTTP(S)_PROXY`, `ALL_PROXY` or the system proxy settings for DSM. With `tls.verify: false` (default) the SHA-256 of the certificate an origin presents on the first connection is stored in `tls.known_certs_file` (mode 600; `nas: trusting the certificate of ... on first use` on stderr) and every later connection must present the same certificate, otherwise the command stops with `the TLS certificate of ORIGIN changed`. After replacing the DSM certificate: `nas trust --reset https://HOST:PORT`. `nas trust` lists the stored fingerprints. With `tls.verify: true` the system CAs decide and nothing is pinned. A notice is printed when the 1Password token file is readable by other users.

**AutoBlock.** DSM blocks an address after 10 failed sign-ins within 5 minutes by default, often permanently. `nas` never retries a failed password. A wrong password in your source costs one attempt per command, so fix the source before running again. Code 407 means the address is already blocked: remove it from Control Panel > Security > Protection > Allow/Block List from another address. See [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) for recovery paths.

## Backends

| Backend | When | How it signs in | Notes |
|---|---|---|---|
| `password` (default) | From any computer that reaches DSM over HTTPS (LAN, VPN, Tailscale) | The credential chain above | Uses `origins` from the config. |
| `chrome` | macOS only, when you are already signed in to DSM in Google Chrome and do not want to store a password anywhere | Runs same-origin requests inside the DSM tab via AppleScript (Chrome: View > Developer > Allow JavaScript from Apple Events) | `upgrade`, `alert-deploy` and `tailscale` run with `--backend password`. |
| `local` | On the NAS itself as root (DSM Task Scheduler), e.g. what `alert-deploy` installs | None: `/usr/syno/bin/synowebapi --exec` runs the API as the system | Runs on the NAS as root. Tailscale status via the `tailscale` binary. |

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

nas incident contain                       # list processes that look like an encryptor (signals nothing without --yes / NAS_YES=1)
nas incident contain --yes                 # SIGSTOP them (all threads) so their memory and keys stay intact
nas incident contain --yes --stop-sync     # also stop Cloud Sync, Synology Drive, Hyper Backup, Container Manager
nas incident contain --yes --save-exe /volumeUSB1/usbshare/evidence   # copy each executable (sha256 recorded)
nas incident contain --release             # SIGCONT the frozen PIDs and start the packages --stop-sync stopped

nas incident rescue --yes --capture-dir /usbshare1/rescue                  # freeze, capture memory, recover key candidates
nas incident rescue --yes --capture-dir /usbshare1/rescue --sample /share/a.pdf.L0CK3D   # test each candidate on a copy
nas incident rescue --yes --capture-dir /usbshare1/rescue --decrypt-from /share/docs --decrypt-to /Volumes/USB/out
```

While files are being encrypted, `nas incident contain --yes` is the first command: it freezes the encryptor (`SIGSTOP`, never killed) so the session keys stay in its memory, then prints the next steps.

- Candidates: known names (`libgld`, `qnetd`, `xdy5*`, `incident.ioc_process_names`), executables in `/tmp`, `/var/tmp`, `/dev/shm`, `/volume*/@tmp`, processes with `*.L0CK3D` / `read-me3.txt` files open for writing, and high CPU outside Synology paths (containers excluded). A process whose executable is under a Synology path (`/usr/syno`, `/var/packages`, `/bin`, ...) needs a reason besides the open files; the scan lists it under `skipped` with the `--pid` that adds it. PID 1, kernel threads and the scanning script with its parents are never signalled, also with `--pid`.
- The freeze signals exactly the processes the scan listed: same PID, start time (`/proc/PID/stat` field 22) and executable; a PID reused in between is reported and skipped.
- `--stop-sync`: after the freeze, each of the packages Cloud Sync, Synology Drive, Hyper Backup and Container Manager (or Docker) that is running is stopped with `SYNO.Core.Package.Control stop`. Stopping Container Manager stops every container. The IDs it stopped are recorded in `contain-packages.json` next to the session cache on this computer.
- `--release`: `SIGCONT` to the PIDs recorded on the NAS (`incident.contain_state_file`) and any `--pid`, then `SYNO.Core.Package.Control start` for each recorded package; the record is deleted once every package started. It starts packages, not single containers: a container comes back when its restart policy (auto-restart in Container Manager) starts it with the package.

`nas incident rescue` does the memory capture and key recovery with [soimy/c3rb3r-rescue](https://github.com/soimy/c3rb3r-rescue), fetched at run time at the commit in `incident.rescue_commit`:

1. `contain`: the freeze above (`--no-contain` skips it).
2. `toolkit`: clones the toolkit and checks the commit (or uses `--rescue-dir`).
3. `capture`: as root on the NAS (temporary Task Scheduler task, or directly with `--backend local`), the toolkit's `capture_process_memory.py inspect` and `capture` for each frozen PID into a new case folder under `--capture-dir`. That folder has to be on a USB disk or another volume than the affected data (`--force` for the same volume).
4. `pull`: downloads the capture to the workdir on this computer (`--keep-on-nas` stops after the capture).
5. `venv`: a venv with the toolkit's pinned requirements (Python `incident.rescue_min_python`, 3.11, or `--python`) and its self-tests.
6. `keys`: `recover_process_key.py` on each capture; candidates are files with mode 400, never printed.
7. `sample` (`--sample NAS_FILE [--expected-sha256 HEX]`): copies the file and tries each candidate on the copy.
8. `decrypt` (`--decrypt-from NAS_FOLDER --decrypt-to DIR`): decrypts copies with the verified candidate.

Each step is recorded in `<workdir>/state.json` (`--workdir`, default `~/.local/share/synology-nas-cli/rescue/<time>`); the same command continues where it stopped. On the NAS it writes only the capture folder. JSON: [`schemas/incident-rescue.schema.json`](schemas/incident-rescue.schema.json).

If the audit shows `ransomware_files FAIL` or `external_signins FAIL` you are past hardening: follow [`docs/INCIDENT-C3RB3R.md`](docs/INCIDENT-C3RB3R.md) (isolate first, keep evidence, restore from snapshots).

## `nas incident fix`

Runs the audit, prints the plan, asks for confirmation (`--yes`, `NAS_YES=1` or `assume_yes: true` answer yes; without a terminal and without those it exits 3 with `Not applied: add --yes (or NAS_YES=1).`), applies the changes in this order, reads each one back, then runs the audit again and prints before -> after. `--dry-run` prints the plan and the exact calls and sends no write. Exit status 1 when a change fails or the final audit still has a FAIL.

Order: `snapshot_worm` -> `snapshots` -> `packages` -> `smb_min_protocol` -> `quickconnect` -> `router_port_forwarding` -> `autoblock` -> `admin_account` -> `firewall` -> `rotate_password` (opt-in) -> `upgrade` (opt-in, reboots).

| Fix | What changes | DSM web UI (manual way) | Raw call (`nas api ... --allow-write`) |
|---|---|---|---|
| `snapshot_worm` | Immutable-snapshot lock off on shares where the model lacks immutable snapshots (gated like `snapshots`: the share's schedule starts taking snapshots again) | Snapshot Replication > Snapshots > Settings (the option is hidden on unsupported models, so the API is the only way) / Snapshot Replication > 快照 > 設定 | `SYNO.DisasterRecovery.Retention set_worm_lock --version 1 type=Share name=SHARE worm_lock_enable=false worm_lock_day=7` |
| `snapshots` | Create a daily schedule (`incident.snapshot_hour:minute`) on shares that have none, with retention by days (`incident.snapshot_retain_days`, 14) only where the share has no retention policy yet. Existing schedules, enabled or not, and existing retention are left alone. Runs after a clean `--ransom-scan` in the same run, or with `--i-know-snapshots-may-rotate` / `--force`: snapshots that start being taken apply retention, which deletes the oldest snapshots | Snapshot Replication > Snapshots > select the share > Settings > Schedule / Retention Policy (Snapshot Replication > 快照 > 設定 > 排程 / 保留原則) | `SYNO.Core.Share.Snapshot set_schedule --version 1 name=SHARE enable_snapshot_schedule=true 'schedule={...}' task_id=-1` then `SYNO.DisasterRecovery.Retention set --version 1 name=SHARE type=Share policyType=64 retainDay=14 ...` |
| `packages` | Stop running packages named in SA-26:14 (update or uninstall them yourself) | Package Center > Installed > package > Update or Stop (套件中心 > 已安裝) | `SYNO.Core.Package.Control stop --version 1 id=PHP7.4` |
| `smb_min_protocol` | Minimum SMB protocol SMB2 (SMB1-only clients lose access) | Control Panel > File Services > SMB > Advanced Settings (控制台 > 檔案服務 > SMB > 進階設定) | `SYNO.Core.FileServ.SMB set --version 3 smb_min_protocol=1 smb_max_protocol=3` |
| `quickconnect` | QuickConnect off, and its automatic router port forwarding off | Control Panel > External Access > QuickConnect (控制台 > 外部存取 > QuickConnect) | `SYNO.Core.QuickConnect set --version 2 enabled=false`; `SYNO.Core.QuickConnect.Upnp set --version 1 enabled=false` |
| `router_port_forwarding` | Disable (not delete) the router port-forwarding rules DSM manages over UPnP/NAT-PMP | Control Panel > External Access > Router Configuration (控制台 > 外部存取 > 路由器設定); also check the router's own page | `SYNO.Core.PortForwarding.Rules save --version 1 'rules=[...enable:false...]' task_id_suffix=PF`, poll `save_status` |
| `autoblock` | AutoBlock on (10 attempts / 5 min); allow-list this computer's address as DSM logged it, the IPv4 `allowed_networks`, and `127.0.0.1` only with `incident.autoblock_allow_loopback` | Control Panel > Security > Protection > Auto Block; Allow/Block List (控制台 > 安全性 > 保護) | `SYNO.Core.Security.AutoBlock set --version 1 enable=true attempts=10 within_mins=5 enable_expire=false expire_day=0`; `SYNO.Core.Security.AutoBlock.Rules create --version 1 type=allow block_days=0 overwrite=true 'ip=["127.0.0.1"]'` |
| `admin_account` | Disable the built-in `admin`. Checks first whether the CLI is signed in as `admin`, which account a pasted `NAS_SID` session uses (`SYNO.Core.Desktop.Initdata`), and whether another enabled member of `administrators` exists; `--force-admin` (or `--force`) applies it whatever those checks say. `SYNO.Core.User set` answers 105 from a password session, so it runs as root in a temporary Task Scheduler task that is deleted afterwards | Control Panel > User & Group > admin > Edit > Disable this account (控制台 > 使用者與群組) | root task script: `/usr/syno/bin/synowebapi --exec api=SYNO.Core.User method=set version=1 name='"admin"' expired='"now"'` (with `--backend local`: `SYNO.Core.User set --version 1 name=admin expired=now`) |
| `firewall` | Enable the firewall; allow rules (this computer's `/32` as DSM logged it + IPv4 `allowed_networks`) on the LAN interfaces (`global` only when the profile has no LAN interface); every interface except `global` (eth*, pppoe, ppp0, vpn, wlan0, ...) drops unmatched traffic; rules that allow any source are removed | Control Panel > Security > Firewall > Edit Rules (控制台 > 安全性 > 防火牆 > 編輯規則) | `SYNO.Core.Security.Firewall.Profile set --version 1 'profile={...}' profile_applying=false`, then `SYNO.Core.Security.Firewall.Profile.Apply start --version 1 name=default profile_applying=false`, poll `status task_id=...`, `stop` |
| `rotate_password` (`--rotate-password`) | New random 24-character password for the signed-in account. Written to the store first (1Password item via `op item edit` on stdin, keeping the old value in the item history; or the keychain entry, with the old value copied to `<store_service>-previous`), then changed in DSM; if DSM rejects it, the old password goes back into the store; if the DSM call is interrupted the store keeps the new one. Read back and a fresh login verified. Never printed. Writes to 1Password or the keychain entry; for a password from a command, env or prompt, change it in DSM and in that source | Personal > Account > change password (個人 > 帳號) | `SYNO.Core.NormalUser set --version 2 password=... old_password=...` |
| `upgrade` (`--upgrade`) | Download the newest official `.pat`, upload, PreCheck, install; the NAS reboots | Control Panel > Update & Restore > Manual DSM Update (控制台 > 更新與還原) | `nas upgrade --yes` |

**Firewall lockout check.** Before the firewall change the CLI checks, and lists in the plan: HTTP(S) proxies are configured for the origin; the origin is a loopback address (SSH tunnel, local proxy) or a public address; the newest successful sign-in of this account in DSM's connection log shows a loopback, IPv6 or public source; or that logged source differs from the local address this computer uses to reach the NAS (NAT, a proxy, or the sign-in came from another device). When a check does not pass, the change waits for `--force-firewall` (or `--force`), which applies it with the check result in the plan note. The allowed set contains the address DSM logged. After applying, it signs in again over the same origin from scratch; if that fails it prints rescue steps: another computer on the LAN, Synology Assistant / find.synology.com, Tailscale userspace mode (DSM sees `127.0.0.1`, which the firewall did not filter in testing), and the RESET button (mode 1). IPv6 allow-list entries are not written as rules, so IPv6 sources are dropped. `100.64.0.0/10` (Tailscale) is also the range CGNAT ISPs use on the WAN side: on a NAS that dials PPPoE itself, a `global` allow rule for it would admit other subscribers, which is why the rules go on the LAN interfaces.

**A NAS with its own public address** (it dials PPPoE itself, or sits in a DMZ) has no router NAT in front of it: the DSM firewall is then the only layer between every DSM service and the internet. QuickConnect and UPnP port forwarding open DSM to the internet even behind NAT.

## MCP server and agent skills

### MCP server (`nas mcp`)

`nas mcp` runs a Model Context Protocol server over stdio (JSON-RPC 2.0; protocol versions `2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05`) exposing 15 tools: `setup`, `doctor`, `whoami`, `status`, `health`, `net`, `services`, `logs`, `alert`, `incident_audit`, `incident_fix`, `pkg_list`, `volume_list`, `tailscale_status`, and `api_read`.

```bash
claude mcp add synology-nas --scope user -- /path/to/synology-nas-cli/bin/nas mcp
claude mcp add synology-nas --scope user -- /path/to/synology-nas-cli/bin/nas mcp --auto-confirm
```

`incident_fix` applies its plan when a call has `confirm: true`, or has no `confirm` on a server started with `--auto-confirm`; `confirm: false` is always a dry run. `NAS_YES` and `assume_yes` do not change MCP calls. The `setup` tool takes `op:`, `keychain` and `env` credential sources; `command:` sources are set with `nas setup` on the command line. Fields such as `user`, `descr`, log `text`, `cmdline` and file names carry text chosen by whoever sends sign-ins to the NAS or runs processes on it.

Full tool list, schemas and configuration for Claude Code, Claude Desktop, Cursor and Codex: [`docs/MCP.md`](docs/MCP.md).

### Agent skills installer

The [`skills/`](skills/) folder contains [`skills/synology-nas/SKILL.md`](skills/synology-nas/SKILL.md) and [`skills/synology-ransomware-response/SKILL.md`](skills/synology-ransomware-response/SKILL.md). Install them into existing skill directories (`~/.claude/skills`, `~/.cursor/skills`, `~/.codex/skills`, `~/.agents/skills`, `~/.grok/skills`, `~/.gemini/skills`, `~/.config/opencode/skills`, `~/.hermes/shared-skills`):

```bash
./skills/install.sh                  # symlink skills into detected agent folders
./skills/install.sh --copy           # copy instead of symlink (--dry-run, --uninstall also available)
```

On Windows PowerShell:

```powershell
.\skills\install.ps1                 # supports --copy, --dry-run, --uninstall
```

## Alerts and webhooks

`nas alert` runs every health and security check once and exits 1 when something is at warning/critical level. Every finding is `{level, code, kind, message}`. With `--push FILE` it POSTs only what changed since the last successful push to `{"url", "header"}` from FILE: new conditions, a reminder every 24 h for warning/critical ones still present, every event, resolved keys, and one heartbeat a day. Codes, the body format and receiver examples are in [`docs/ALERTS.md`](docs/ALERTS.md).

Three ways to run it:

1. **On the NAS, set up for you:** `nas alert-deploy` copies the code into a root-only folder (`deploy.root_dir`), creates a root Task Scheduler task running `nas --backend local alert --push` every 10 minutes, and points DSM's own notification webhook (Control Panel > Notification > Webhooks) at the same URL.
2. **On the NAS, by hand:** the same three pieces done in DSM's UI. Steps in [`docs/ALERTS.md`](docs/ALERTS.md#manual-install-on-the-nas).
3. **From another always-on machine:** cron or launchd running `nas alert --push ...` with the `password` backend. See [`docs/ALERTS.md`](docs/ALERTS.md#from-another-machine-cron--launchd).

Receivers: any HTTPS endpoint that takes a JSON POST with one header (generic JSON receiver), a chat-bot "routine" webhook that starts an agent run per POST (Grok-Bot-style), or no webhook at all: DSM's built-in notifications (email, Synology mobile push through the DS finder / Synology app) cover DSM's own warning/error events. All three are in [`docs/ALERTS.md`](docs/ALERTS.md#receivers).

## Command reference summary

```bash
nas setup --origin URL --user USER --password-source SOURCE   # write the config, sign in once, pin the certificate
nas doctor        # config, credentials, origin, TLS, login, DSM version, 2FA, capabilities, clock
nas whoami        # backend, origin, credential source, session, account, admin flag, DSM version
nas status        # model, DSM version, uptime, SA-26:13 verdict
nas net           # interfaces, PPPoE (public address), firewall, gateway
nas services      # SSH / FTP / SMB / AFP / NFS / rsync / QuickConnect / AutoBlock / DSM ports
nas inventory     # shares, packages (SA-26:14 flags), containers, users (2FA), scheduled tasks
nas health        # disks (SMART, temperature), pools, volumes, UPS, CPU, memory
nas logs --since "2026-10-30 00:00" --top 5   # failed sign-ins by user/IP, external successes
nas ransom-scan   # File Station search for *.L0CK3D, *.LOCK3D, read-me3.txt (one task per pattern)
nas exposure      # TCP probe of LAN and public addresses from this machine
nas incident [--probe] [--scan] [--deep] [--hours 24] [--failed-threshold 20]
nas incident fix [--dry-run] [--yes] [--only LIST] [--skip LIST] [--share S] [--ransom-scan] [--upgrade] [--rotate-password]
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
nas --no-input <command>                                      # prompts answer with exit 3 (also NAS_NO_INPUT=1; automatic without a terminal)
nas --yes <command>                                           # accept every confirmation (also NAS_YES=1, config assume_yes; see "What changes the NAS")
nas --force incident fix --yes                                # apply changes whose checks do not pass (--force-firewall, --force-admin, snapshot rotation, reinstall)
nas mcp [--auto-confirm]                                      # MCP server on stdio (docs/MCP.md)
```

### Documentation index

- [`docs/AGENT-RUNBOOK.md`](docs/AGENT-RUNBOOK.md) — Step-by-step sequence for AI agents (`setup` → `doctor` → `incident` → `incident fix` → `--deep` → `alert-deploy`).
- [`docs/INCIDENT-C3RB3R.md`](docs/INCIDENT-C3RB3R.md) — Public incident page for the 2026 C3RB3R / `.L0CK3D` ransomware campaign, advisories, timeline, IOCs, decision steps, recovery and prevention.
- [`docs/HARDENING.md`](docs/HARDENING.md) — Synology DSM security hardening checklist with sourced explanations, English / 繁體中文 DSM UI paths, and matching `nas` commands.
- [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) — Solutions for firewall/AutoBlock/2FA lockouts, Mode 1 reset, reverse proxies and Tailscale `127.0.0.1`, unsupported WORM models, Google Drive 750 GB/day quota, SMB1 devices, DSM API error codes, "up to date" branch traps, and TLS pin resets.
- [`docs/MCP.md`](docs/MCP.md) — MCP server tools, arguments, schemas, and client setup.
- [`docs/GROK-BOT.md`](docs/GROK-BOT.md) — Grok Bot: `nas` on the bot's cloud computer (Tailscale) or on a computer with the Grok Bot app, skills, the alert routine webhook, and a bot description.
- [`docs/ALERTS.md`](docs/ALERTS.md) — Alert codes, webhook payload, receivers, and deployment (`alert-deploy`, manual DSM task, cron/launchd).
- [`docs/DSM-API-NOTES.md`](docs/DSM-API-NOTES.md) — DSM 7 Web API quirks and parameter encoding rules relied on by `nas`.
- [`docs/EXIT-CODES.md`](docs/EXIT-CODES.md) — CLI and MCP `_meta.exit_code` definitions (`0`–`7`, `130`).
- [`schemas/`](schemas/) — JSON Schemas for `incident`, `incident-fix`, `incident-contain`, `incident-rescue`, `alert`, `status`, `health`, and `whoami`.
- [`llms.txt`](llms.txt) — Entry-point index for LLM agents.

## What changes the NAS

- Commands that change the NAS: `incident fix` (asks, or `--yes`), `incident contain` (`SIGSTOP` with `--yes`; `--stop-sync` stops packages; `--release`), `incident rescue` (asks, or `--yes`: freeze, temporary root tasks, the capture folder), `upgrade` (without `--yes` it still uploads the `.pat` and runs PreCheck, then deletes the upload; `--yes` installs), `pkg start|stop|install|uninstall|default-volume VOL`, `volume atime`, `tailscale login-url`, `alert-deploy`, `login --save` / `logout --forget` (local keychain only), `trust --reset` (local file), and `api` with `--allow-write`. `ransom-scan`, `incident --scan` and `incident fix --ransom-scan` create temporary File Station search tasks on the NAS (stopped and cleaned afterwards). `nas api` sends methods that are not reads with `--allow-write`, `--yes` or `NAS_YES=1`.
- `--yes`, `NAS_YES=1` and config `assume_yes: true` answer every confirmation of the CLI: `incident fix` applies its plan (with `--upgrade` it installs DSM and the NAS reboots, a PreCheck with notes included; with `--rotate-password` it changes the password); `upgrade` installs after PreCheck and the NAS reboots; `incident contain` freezes the candidates (and with `--stop-sync` stops the packages); `incident rescue` runs its steps; `api` sends write methods as with `--allow-write`. `nas mcp` takes its answer from each call's `confirm` and from `--auto-confirm`, not from these.
- `incident fix --dry-run` prints every write call it would send. The plan always shows current -> new values.
- Passwords, SIDs and SynoTokens are never printed. `nas api` prints raw DSM output, which can include serial numbers and account names; the other commands filter those.
- Each password sign-in that fails counts toward AutoBlock; the CLI reports a failed sign-in once and stops.
- `alert-deploy` installs code that runs as root on the NAS in a root-only folder outside the shared folders.

## Tests

```bash
tests/run_offline.sh      # all offline tests with python3, and with Python 3.8 when `uv python find 3.8` works
tests/smoke_live.sh       # optional: read-only commands against your NAS (uses your config)
```

---

## 繁體中文說明

**一個指令檢查 Synology NAS 是否有 C3RB3R／`.L0CK3D` 勒索軟體攻擊活動相關的弱點與入侵指標，第二個指令依計畫把問題修好；日常也能直接在終端機或透過 AI Agent 管理與監控 DSM。**

`nas` 是僅依賴 Python 標準函式庫（Python 3.8+，因此也能直接在 DSM 內建環境執行）的命令列工具與 MCP 伺服器，支援 DSM 7 Web API：系統狀態、硬碟與儲存空間健康度、連線紀錄、套件管理、儲存空間 `noatime`、Tailscale、DSM 自動下載與升級、排程健康檢查與 Webhook 推播，以及針對 2026 年 C3RB3R／`.L0CK3D` 勒索攻擊（Synology-SA-24:20、SA-26:13、SA-26:14）設計的唯讀稽核與一鍵修復流程。本專案與 Synology Inc. 無關。

### 交給 AI Agent 自動執行

把以下提示詞貼給 Claude Code、Codex、Cursor、Gemini CLI、Grok Bot 或任何支援工具呼叫的 AI Agent（Grok Bot 的雲端電腦／裝了 App 的電腦怎麼跑 `nas`、skills、警報例行任務：[`docs/GROK-BOT.md`](docs/GROK-BOT.md)）：

```text
使用 https://github.com/akari-sora/synology-nas-cli 檢查並修復我的 Synology NAS（位址：https://192.0.2.10:5001），照著 docs/AGENT-RUNBOOK.md 的步驟執行。
```

#### Agent 會依序執行的步驟

1. **安裝**：複製此儲存庫（或用 `pip` 安裝）並執行 `./bin/nas --version` 確認環境。
2. **`nas setup`**：執行 `nas setup --json --no-input ...` 寫入 `~/.config/synology-nas-cli/config.json`（權限 `0600`）、進行首次登入驗證，並在首次連線時釘選（pin）DSM 的 TLS 憑證 SHA-256 指紋。
3. **`nas doctor`**：執行 `nas doctor --json` 檢查設定檔、憑證來源、連線可達性、TLS 指紋、登入狀態、DSM 版本（比對 SA-26:13）、兩步驟驗證（2FA）、管理員權限與系統時鐘偏差。
4. **`nas incident`**：執行 `nas incident --json`（可加 `--probe --scan`）進行唯讀安全稽核。
5. **產生修復計畫**：執行 `nas incident fix --dry-run --json --ransom-scan`，列出每一項變更的前後對照（`before -> after`）、實際會發送的 DSM API 呼叫與 DSM 網頁介面路徑。
6. **套用修復（`nas incident fix --yes`）**：依安全順序套用修復、逐項讀回設定確認生效，並重跑一次稽核輸出前後對比。
7. **進階入侵指標檢查與監控部署（選用）**：執行 `nas incident --deep --json`（透過暫時性 root 排程任務執行唯讀腳本，檢查 root 專屬日誌、排程、可疑執行檔、帳號、SSH 金鑰與程序）以及 `nas alert-deploy --json --test`（每 10 分鐘自動檢查並推播異常到 Webhook）。

#### 使用者沿途只需提供的資訊

1. **NAS 位址與帳號（一次）**：DSM 網址（例如 `https://192.0.2.10:5001`）、管理員帳號名稱、密碼來源（1Password `op://VAULT/ITEM/password`、密碼指令或系統鑰匙圈）、防火牆要放行的區網／VPN 網段（例如 `192.0.2.0/24`），以及供 `--deep` 與 `alert-deploy` 暫存檔案的共用資料夾路徑（例如 `/docker/.nas-cli-deploy`）。
2. **兩步驟驗證碼（若帳號已啟用 2FA，僅需一次）**：當 `nas setup` 回報需要 `otp` 時提供當下的 6 位數驗證碼；加上 `--trust-device` 後會儲存 DSM 的信任裝置權杖，之後執行不需再輸入驗證碼。
3. **確認修復計畫**：檢視 `--dry-run` 列出的變更內容（並決定是否加上選用的 `--rotate-password` 換密碼或 `--upgrade` 升級 DSM）。

### `nas incident` 檢查項目與 `nas incident fix` 修復內容

| 項目 | `nas incident` 檢查內容 | `nas incident fix` 變更內容 |
|---|---|---|
| `dsm_version` | DSM 版本是否低於 SA-26:13 修補版本，或處於無修補程式的舊分支（DSM 7.1 及更舊版本） | 加 `--upgrade` 時自動下載官方最新 `.pat`、執行 PreCheck 並安裝重開機 |
| `sa_26_14_packages` | Calendar、MailStation、PHP 7.3–8.4 是否低於 SA-26:14 修補版本（執行中為 `FAIL`，已停止為 `WARN`） | 停止正在執行的未修補套件（`--only packages`） |
| `firewall` | 防火牆未開（NAS 自己撥 PPPoE 持有公網 IP 時為 `FAIL`），或開啟但介面預設允許未比對流量、規則允許任意來源（`source_ip: all`） | 啟用防火牆、在區網介面放行本機 `/32`（依 DSM 連線紀錄）與 `allowed_networks` 的 IPv4 網段、將所有非 `global` 介面設為預設丟棄（`drop`），並移除允許任意來源的規則（`--only firewall`） |
| `quickconnect` | QuickConnect 或其自動路由器連接埠轉送開啟 | 關閉 QuickConnect 與其 UPnP 自動連接埠轉送（`--only quickconnect`） |
| `router_port_forwarding` | DSM 在路由器上設有啟用中的 UPnP／NAT-PMP 連接埠轉送規則 | 停用 DSM 管理的路由器連接埠轉送規則（`--only router_port_forwarding`） |
| `public_ports` | 搭配 `--probe`：從本機對 NAS 公網位址測試 DSM 與檔案服務連接埠是否可連上 | 透過 `firewall`、`quickconnect` 與 `router_port_forwarding` 關閉暴露面 |
| `external_signins` | 連線紀錄中是否有來自 `allowed_networks` 以外的成功登入紀錄 | 不自動修改（需人工調查是否遭入侵，見 [`docs/INCIDENT-C3RB3R.md`](docs/INCIDENT-C3RB3R.md)） |
| `failed_signins` | 過去 `--hours`（預設 24 小時）內登入失敗次數超過 `--failed-threshold`（預設 20 次） | 透過 `firewall` 與 `autoblock` 阻擋 |
| `autoblock` | 自動封鎖（AutoBlock）未啟用 | 啟用自動封鎖（5 分鐘內失敗 10 次永久封鎖），並將本機 IP 與 `allowed_networks` 加入允許清單（若設定 `incident.autoblock_allow_loopback` 亦會加入 `127.0.0.1`）（`--only autoblock`） |
| `smb_min_protocol` | 允許 SMB1（SMB 啟用時為 `FAIL`） | 將 SMB 最低通訊協定調升為 SMB2（`--only smb_min_protocol`） |
| `admin_account` | 內建 `admin` 帳號仍處於啟用狀態 | 確認目前非以 `admin` 登入且另有其他啟用中的管理員後，透過暫時性 root 排程任務停用 `admin`（`--only admin_account`） |
| `snapshot_schedule:<share>` | 各共用資料夾是否未設排程快照、排程停用，或最近一次排程快照超過 `snapshot_max_age_hours`（26 小時） | 為尚無排程的共用資料夾建立每日快照排程與 14 天保留原則；需同次執行乾淨的 `--ransom-scan` 或加 `--i-know-snapshots-may-rotate`（`--only snapshots`） |
| `snapshot_worm:<share>` | 在不支援不可變快照（WORM）的機型上誤開 WORM 鎖定（DSM API 會回傳成功，但排程快照會從此靜默停擺） | 關閉不支援機型上的 WORM 鎖定，讓排程快照恢復運作（`--only snapshot_worm`） |
| `ransomware_files` | 搭配 `--scan`：透過 File Station 搜尋所有共用資料夾是否有 `*.L0CK3D`、`*.LOCK3D` 或 `read-me3.txt` | 不自動修改（若為 `FAIL` 請立即隔離並依 [`docs/INCIDENT-C3RB3R.md`](docs/INCIDENT-C3RB3R.md) 處置） |
| `exploit_attempts` | 掃描連線紀錄是否有 CVE-2024-10441 登入注入字串（`PLUGIN_VALUE_END`、`LD_PRELOAD=`、`LD_DEBUG_OUTPUT`）或 `incident.ioc_ips` | 不自動修改（可進一步執行 `--deep` 確認是否成功植入） |
| `exploit_attempts_logs`、`ioc_cron`、`ioc_binaries`、`ioc_users`、`ioc_ssh_keys`、`ioc_processes` | 搭配 `--deep`：執行唯讀 root 收集器檢查 `/var/log/synoplugin.log*`、`synoscgi.log*`、`auth.log*`、`/etc/cron.d/synot*`、`/bin/libgld`、`/bin/qnetd`、`/bin/l0ck.enc`、異常帳號、`authorized_keys` 與 `/proc` 程序／外部連線 | 不自動修改（若為 `FAIL` 請依 [`docs/INCIDENT-C3RB3R.md`](docs/INCIDENT-C3RB3R.md) 進行事件應變） |

### 正在被加密時：`nas incident contain`、`nas incident rescue`

- `nas incident contain`：列出疑似加密程式的程序（`libgld`、`qnetd`、從暫存資料夾執行的程式、以寫入模式開著 `*.L0CK3D` 或 `read-me3.txt` 的程序）。沒加 `--yes`／`NAS_YES=1` 時不送任何訊號。執行檔在 Synology 路徑下的程序，除了開著的檔案之外還需要另一個理由才會列入（列在 `skipped`，附上加入用的 `--pid`）。PID 1、核心執行緒、掃描腳本本身與其上層程序一律不送訊號（`--pid` 也一樣）。
- `nas incident contain --yes --stop-sync`：對掃描列出的程序（PID、啟動時間、執行檔都相同者）送 `SIGSTOP`（所有執行緒，逐一確認狀態為 `T`），讓金鑰留在記憶體裡；同時停止執行中的 Cloud Sync、Synology Drive、Hyper Backup 和 Container Manager 套件（停止 Container Manager 會停止所有容器），停掉的套件記錄在本機工作階段快取旁的 `contain-packages.json`。
- `--save-exe DIR` 另存執行檔與 sha256；`nas incident contain --release` 對記錄的 PID 送 `SIGCONT`，並啟動 `--stop-sync` 停掉的套件（容器依各自的重新啟動原則回來）。
- `nas incident rescue --yes --capture-dir /usbshare1/rescue`：用 [soimy/c3rb3r-rescue](https://github.com/soimy/c3rb3r-rescue)（執行時依 `incident.rescue_commit` 下載）一路做完：凍結 → 取得工具並核對 commit → 在 NAS 上以 root 對每個凍結的 PID 執行 `capture_process_memory.py`，寫到 `--capture-dir` 底下的新資料夾（須在 USB 硬碟或與受害資料不同的磁碟區，同一磁碟區要加 `--force`）→ 下載到本機 → 建 venv、安裝固定版本套件並跑自我測試 → `recover_process_key.py` 找出金鑰候選（檔案權限 400，不會印出）。`--sample 檔案` 在副本上逐一試候選金鑰，`--decrypt-from 資料夾 --decrypt-to 目錄` 解密副本。每一步記錄在工作目錄的 `state.json`，同一個指令再跑一次會從中斷處繼續。

### 安裝與環境設定

```bash
# 方式一：git clone 後直接執行（不需額外安裝套件）
git clone https://gitlab.com/aa22396584/synology-nas-cli.git synology-nas-cli
cd synology-nas-cli
./bin/nas --help

# 方式二：使用 pip 從 GitLab release 或本地目錄安裝
pip install https://gitlab.com/aa22396584/synology-nas-cli/-/archive/v1.0.0/synology-nas-cli-v1.0.0.tar.gz
# 或：pip install -e .

# 方式三：Windows 使用 py 啟動器
py -3 bin\nas --help
py -3 -m pip install -e .
```

依作業系統與環境選擇設定方式：

- **macOS 搭配 1Password**：`credentials.op_password` 填 `op://VAULT/ITEM/password`，透過 1Password App 授權 `op` 讀取密碼與 2FA 驗證碼。
- **macOS 不使用 1Password**：執行 `nas login --save` 存入 macOS 鑰匙圈，或設 `password_command` 為 `security find-generic-password -s synology-nas -a USER -w`。
- **Linux 伺服器／cron／systemd**：使用 1Password Service Account（`OP_SERVICE_ACCOUNT_TOKEN` 或 token 檔案）搭配 `op://`，或設 `password_command`（`secret-tool lookup ...`、`pass show ...`）。
- **Windows**：以 PowerShell `CredentialManager` 模組儲存憑證，並在 `password_command` 呼叫 `Get-StoredCredential`，或使用環境變數 `NAS_USER` + `NAS_PASSWORD`。
- **在 NAS 本機上執行**：使用 `--backend local`（由 DSM 任務排程表以 `root` 執行 `synowebapi --exec`，不需密碼；`nas alert-deploy` 會自動部署）。

### 憑證、TLS、防火牆與 AutoBlock 重點

- **憑證優先順序**：1Password（`op`）→ 外部指令（`command`）→ 系統鑰匙圈（`keychain`，由 `nas login --save` 寫入）→ 環境變數（`env`）→ 終端機互動輸入（`prompt`）。
- **TLS 憑證釘選**：`password` 後端連線 DSM 絕不經過任何系統或環境變數 Proxy。預設 `tls.verify: false` 會在首次連線時將憑證 SHA-256 指紋寫入 `~/.config/synology-nas-cli/known-certs.json`（權限 `0600`）；之後若憑證變更會拒絕連線並以結束碼 `7` 停止。更新憑證後可執行 `nas trust --reset https://HOST:PORT`。
- **防火牆防自鎖機制**：套用防火牆前會比對 DSM 連線紀錄中的登入來源 IP 與本機連線 IP；若經過 Proxy、來源為 loopback／IPv6／公網 IP 或兩者不一致，會暫緩套用並提示使用 `--force-firewall`。套用後會立即重新登入驗證；若失敗會列出救援方式（區網其他電腦、Synology Assistant、Tailscale userspace 模式、機身背面 RESET 鍵 Mode 1）。
- **AutoBlock 注意事項**：DSM 預設 5 分鐘內登入失敗 10 次即封鎖來源 IP。`nas` 遇到密碼錯誤只會嘗試一次並立即停止，絕不重試。

### MCP 伺服器、Skills 與監控推播

- **MCP 伺服器**：執行 `nas mcp` 啟動 stdio MCP 伺服器（詳見 [`docs/MCP.md`](docs/MCP.md)）。
- **Skills 安裝器**：執行 `./skills/install.sh`（Windows 為 `.\skills\install.ps1`）將 `synology-nas` 與 `synology-ransomware-response` 安裝至各 AI Agent 的技能目錄（支援 `--copy`、`--dry-run`、`--uninstall`）。
- **排程監控與 Webhook**：`nas alert --push webhook.json` 僅在狀態變化、警告持續滿 24 小時或每日一次心跳時發送 POST；`nas alert-deploy --test` 可一鍵部署至 NAS 以 root 每 10 分鐘執行，並同步設定 DSM 內建通知 Webhook（詳見 [`docs/ALERTS.md`](docs/ALERTS.md)）。
- **Grok Bot**：`nas` 可以跑在 Bot 的雲端電腦（透過 Tailscale 連 NAS），或裝了 Grok Bot App 的電腦；skills 用 `gbot skills add` 加入，警報接到 Bot 的例行任務 webhook（詳見 [`docs/GROK-BOT.md`](docs/GROK-BOT.md)）。
- **更多文件**：[`docs/AGENT-RUNBOOK.md`](docs/AGENT-RUNBOOK.md)、[`docs/INCIDENT-C3RB3R.md`](docs/INCIDENT-C3RB3R.md)、[`docs/HARDENING.md`](docs/HARDENING.md)、[`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md)、[`docs/DSM-API-NOTES.md`](docs/DSM-API-NOTES.md)、[`docs/EXIT-CODES.md`](docs/EXIT-CODES.md)。

## License

MIT, Copyright (c) 2026 Akari Sora. See [LICENSE](LICENSE).
