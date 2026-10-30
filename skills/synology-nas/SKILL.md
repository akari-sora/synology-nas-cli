---
name: synology-nas
description: Operate a Synology NAS (DSM 7) from the command line with the `nas` CLI from synology-nas-cli - status, health, disks, UPS, connection logs, packages, volumes, Tailscale, DSM upgrades, alerts and raw DSM Web API calls. Use for Synology, DSM, NAS status or health, "is my NAS ok", SMART, storage pool, Package Center, QuickConnect, AutoBlock, DSM firewall, DSM API errors 119/400/403/407/499, synowebapi, Task Scheduler on DSM.
---

# Synology NAS through `nas`

`nas` is a Python CLI (stdlib only, Python 3.8+) for the DSM 7 Web API. Run it as `nas` (installed with `pip install -e .` or linked onto PATH) or as `bin/nas` from the repository. Every command accepts `--json` (put it before the command: `nas --json status`).

## Configuration

- Config file: `$NAS_CONFIG`, else `~/.config/synology-nas-cli/config.json`. `nas config init` writes an example; `nas config show` prints the effective config (commands masked) and which credential source is active.
- `origins`: DSM URLs tried in order (first one accepting TCP within 3 s), e.g. LAN first, VPN/Tailscale second. `NAS_ORIGINS` or `--lan-origin URL,URL` override it for one run.
- `nas whoami` signs in once and prints backend, origin, credential source, session mode, account, admin flag and DSM version. It is the quickest check that config and credentials work.

## Credentials (first configured source wins)

1. `credentials.op_password` / `op_username` = `op://VAULT/ITEM/FIELD` (1Password CLI; token from `OP_SERVICE_ACCOUNT_TOKEN`, else the token file `credentials.op_token_file`, else the signed-in 1Password app).
2. `NAS_PASSWORD_COMMAND` or `credentials.password_command`: a command printing the password (Keychain `security find-generic-password -w`, `secret-tool lookup`, `pass show`, `bw get password`, PowerShell CredentialManager).
3. The OS keychain entry written by `nas login --save`.
4. `NAS_USER` + `NAS_PASSWORD`.
5. An interactive prompt when stdin is a terminal.

`NAS_CREDENTIAL_SOURCE=op|command|keychain|env|prompt` forces one. 2FA codes: `credentials.otp_command`, else `op item get --otp`, else a prompt; `nas login --trust-device` stores DSM's trusted-device token.

Sessions: by default each command signs in and out. `nas login` caches the session (mode 600) and later commands reuse it, signing in again on 106/107/119; `nas logout` ends it. `NAS_SID` + `NAS_SYNOTOKEN` reuse an existing DSM session.

## Backends

- `--backend password` (default): HTTPS with the credential chain.
- `--backend chrome`: macOS only; uses a DSM tab already signed in in Google Chrome (needs View > Developer > Allow JavaScript from Apple Events). No uploads.
- `--backend local`: on the NAS as root (Task Scheduler); `synowebapi --exec`, no credentials.

## Commands

| Need | Command |
|---|---|
| Model, DSM build, SA-26:13 verdict | `nas status` |
| Disks, SMART, temperatures, pools, volumes, UPS, CPU, memory | `nas health` |
| Interfaces, PPPoE public address, firewall | `nas net` |
| SSH/FTP/SMB/AFP/NFS/rsync/QuickConnect/AutoBlock | `nas services` |
| Shares, packages (SA-26:14), containers, users and 2FA, scheduled tasks | `nas inventory` |
| Failed and external sign-ins | `nas logs [--since "YYYY-MM-DD HH:MM"] [--top N]` |
| Ransomware incident audit / fix | `nas incident`, `nas incident fix --dry-run` (see the synology-ransomware-response skill) |
| Ports reachable from this machine | `nas exposure` |
| One-pass monitoring (exit 1 on warning/critical) | `nas alert --no-update` |
| Packages | `nas pkg list|start ID|stop ID|install ID|uninstall ID [--remove-data]|default-volume [/volumeN]` |
| Volume atime | `nas volume list`, `nas volume atime volume_1 noatime` |
| Tailscale package | `nas tailscale status`, `nas tailscale login-url [--force]` |
| DSM update | `nas upgrade --dry-run`, `nas upgrade` (PreCheck only), `nas upgrade --yes` (installs, reboots) |
| Any API | `nas api SYNO.Core.System info --version 1`; methods that are not reads need `--allow-write` |

Find API names and versions: `nas api SYNO.API.Info query --version 1 query=all` (or `query=SYNO.Core.Foo`). Parameters are `k=v`; values that are not valid JSON are sent as JSON strings automatically.

## Errors

| Code | Meaning |
|---|---|
| 400 | wrong account or password (counts toward AutoBlock) |
| 401 | account disabled |
| 403 / 404 / 406 | 2FA code required / wrong / enforced but not enrolled |
| 407 | this source address is blocked by AutoBlock |
| 498 / 499 | DSM is installing an update / not ready after an upgrade (`nas upgrade --wait-only` waits for `dsm_upgrade_all_done`) |
| 105 | insufficient privilege (non-admin, or a call that also wants `SYNO.Core.User.PasswordConfirm`) |
| 106 / 107 / 119 | session timed out / replaced / not found; 119 on a fresh session means the SynoToken was not in the URL |
| 102 / 103 / 104 | API / method / version not available; check `SYNO.API.Info` |
| 114 / 120 | missing / invalid parameter; often JSON encoding |

## Technical cautions

- AutoBlock (DSM default): 10 failed sign-ins within 5 minutes block the source address, often permanently (`expire_day 0`). The CLI does not retry a failed password; each rerun with the same wrong password adds a failure. Unblocking: Control Panel > Security > Protection > Allow/Block List from another address. Tailscale's DSM package in userspace mode makes every tailnet device appear as `127.0.0.1`, so a block on `127.0.0.1` locks out the whole tailnet.
- DSM 7 APIs with `requestFormat: JSON` JSON-decode every field. A bare string can be accepted, rejected (120), or silently ignored (`SYNO.Core.Package.Uninstallation` answers success and does nothing). Fields that take "a string containing JSON" need double encoding.
- The SynoToken is accepted only as a URL query parameter.
- `synowebapi` prints a `[Line N] Exec WebAPI:` banner before its JSON.
- `SYNO.Core.TaskScheduler run` only runs a task with version 2; version 1 answers success and does nothing.
- `SYNO.Core.User set` (disable an account, change another user) answers 105 from a password session even after `PasswordConfirm`; it works as root through `synowebapi` in a one-off root Task Scheduler task. `SYNO.Core.NormalUser set` v2 changes your own password from a normal session.
- On models without immutable snapshots, turning the WORM lock on through the API is accepted and scheduled snapshots then stop silently (`nas incident` reports it as `snapshot_worm:<share>` FAIL).
- Applying a default-deny firewall profile drops sessions from addresses it does not allow, including your own if you connected through the public address.
- The connection log keeps about the last 10,000 entries; under brute force that is a few hours.
- More API detail: `docs/DSM-API-NOTES.md` in the repository.
