# Troubleshooting Synology DSM hardening, recovery, and CLI errors

Common issues encountered when hardening or operating a Synology NAS with `nas`, each organized as **Symptoms → Cause → Fix** with source references.

- [1. Firewall or AutoBlock lockout and the RESET-button Mode 1 path](#1-firewall-or-autoblock-lockout-and-the-reset-button-mode-1-path)
- [2. AutoBlock vs. reverse proxies and Tailscale (`127.0.0.1`)](#2-autoblock-vs-reverse-proxies-and-tailscale-127001)
- [3. Immutable snapshots (WORM) not offered on some models — or silently stopping scheduled snapshots](#3-immutable-snapshots-worm-not-offered-on-some-models--or-silently-stopping-scheduled-snapshots)
- [4. Hyper Backup to Google Drive quota errors](#4-hyper-backup-to-google-drive-quota-errors)
- [5. SMB1-only devices losing access after raising the minimum SMB version](#5-smb1-only-devices-losing-access-after-raising-the-minimum-smb-version)
- [6. 2-step verification (2FA) lockout](#6-2-step-verification-2fa-lockout)
- [7. DSM Web API errors 105 / 106 / 107 / 119 / 400 / 403 / 404 / 407 (and 498 / 499)](#7-dsm-web-api-errors-105--106--107--119--400--403--404--407-and-498--499)
- [8. The "DSM says up to date but is not" case](#8-the-dsm-says-up-to-date-but-is-not-case)
- [9. TLS certificate pin changes (`nas trust`)](#9-tls-certificate-pin-changes-nas-trust)

---

## 1. Firewall or AutoBlock lockout and the RESET-button Mode 1 path

### Symptoms

- `nas` exits with code `5` (`DSM AutoBlock has blocked this address`, login error `407`) or code `6` (`NAS unreachable`, TCP connection times out or is dropped after applying firewall rules).
- The DSM web interface (`https://192.0.2.10:5001`) does not load from your computer, or displays an IP-blocked message.

### Cause

- **AutoBlock:** DSM blocks a source IP address after repeated failed login attempts (default threshold: 10 failed sign-ins within 5 minutes, permanent block with `expire_day: 0`) ([Synology Community thread](https://community.synology.com/enu/forum/1/post/126260), [cmeans/mcp-synology #447](https://github.com/cmeans/mcp-synology/issues/447)). AutoBlock tracks the source IP address rather than the account name.
- **Firewall:** Applying a default-deny DSM firewall profile drops connections from any source IP not matched by an `allow` rule on that network interface ([Synology Firewall Help](https://kb.synology.com/en-global/DSM/help/DSM/AdminCenter/connection_security_firewall?version=7), [Infomaniak Synology reset FAQ](https://www.infomaniak.com/en/support/faq/2367/restart-and-reset-a-synology-nas)). (`nas incident fix` checks the source IP DSM logged for your session before applying firewall rules and holds the change back unless `--force-firewall` or `--force` is passed.)

### Fix

1. **From another allowed device on the LAN:**
   - Sign in to DSM from another computer on an allowed LAN subnet.
   - For AutoBlock (`407`): open `Control Panel > Security > Protection > Allow/Block List` (`控制台 > 安全性 > 保護 > 允許/封鎖清單`), remove your blocked IP from the Block List, and add your LAN subnet to the Allow List.
   - For Firewall: open `Control Panel > Security > Firewall > Edit Rules` (`控制台 > 安全性 > 防火牆 > 編輯規則`) and add an allow rule for your subnet on the LAN interface.
2. **Over Tailscale (userspace networking mode):**
   - If the Tailscale package is running on the NAS in its default userspace networking mode, `tailscaled` proxies incoming tailnet connections to DSM via `127.0.0.1`, which the DSM interface firewall did not filter in testing ([Tailscale issue #21747](https://github.com/tailscale/tailscale/issues/21747)). Connect using the NAS's `100.x.y.z` tailnet address or MagicDNS name.
3. **Physical RESET button — Mode 1 reset (preserves all volume data):**
   - Locate the recessed `RESET` button on the back of the Synology NAS and press and hold it with a paperclip for **about 4 seconds until you hear a single beep**, then release immediately ([Synology KB: How do I reset my Synology NAS? (DSM 6.2.4+)](https://kb.synology.com/en-global/DSM/tutorial/How_to_reset_my_Synology_NAS_7)).
   - Do **not** press and hold a second time within 10 seconds (3 beeps triggers Mode 2, which wipes the DSM operating system and requires reinstalling DSM).
   - **What Mode 1 resets:**
     - Restores the built-in `admin` account to default settings and turns off 2FA for `admin`.
     - Resets DSM HTTP/HTTPS ports to `5000`/`5001`.
     - Resets network interfaces to DHCP and disables PPPoE.
     - **Disables AutoBlock and disables all DSM firewall rules.**
     - Unjoins High Availability / VMM clusters; on DSM 7.2 and earlier, locks encrypted shared folders and erases the key manager vault (on DSM 7.3+ encrypted volumes stay set to unlock on boot by default).
     - **All shared folder and volume data on the drives remains untouched.**
   - Discover the NAS's DHCP address using [finds.synology.com](https://finds.synology.com) or Synology Assistant, sign in as `admin`, set a strong password on `admin`, fix the firewall / AutoBlock rules for your regular administrator account, and then run `nas incident fix --only admin_account --yes` to deactivate `admin` again.

---

## 2. AutoBlock vs. reverse proxies and Tailscale (`127.0.0.1`)

### Symptoms

- After several failed login attempts by one remote user (or an internet scanner hitting your reverse proxy), **every** user connecting through the reverse proxy or across your Tailscale tailnet gets error `407` (IP blocked by AutoBlock).

### Cause

- **Reverse proxy:** When DSM sits behind Nginx, Synology Application Portal's reverse proxy, Caddy, or Cloudflare Tunnel without trusted proxy headers, DSM sees every incoming connection as originating from the reverse proxy's IP address; 10 failed sign-ins from any external client cause AutoBlock to block the proxy IP itself ([Synology DSM Protection Help](https://kb.synology.com/en-global/DSM/help/DSM/AdminCenter/connection_security_protection?version=7), [Synology Community post 120081](https://community.synology.com/enu/forum/1/post/120081)).
- **Tailscale userspace mode vs. TUN mode:** On DSM 7, the Tailscale package runs in userspace networking mode by default because non-root packages lack `/dev/net/tun` access; `tailscaled` relays inbound tailnet connections to DSM from `127.0.0.1` ([Tailscale localhost forum](https://forum.tailscale.com/t/why-does-localhost-work/4240), [Tailscale issue #21747](https://github.com/tailscale/tailscale/issues/21747)). Consequently, DSM logs tailnet connections as coming from `127.0.0.1`, and an AutoBlock trigger on `127.0.0.1` blocks all tailnet clients. Conversely, if you enable outbound TUN mode via a boot-time root task (`/var/packages/Tailscale/target/bin/tailscale configure-host`), the DSM firewall applies to the `tailscale0` interface and drops traffic unless `100.64.0.0/255.192.0.0` (`100.64.0.0/10`) is allowed ([Tailscale Synology KB](https://tailscale.com/kb/1131/synology)).

### Fix

1. **For Tailscale userspace mode (`127.0.0.1`):**
   - Set `"autoblock_allow_loopback": true` under `"incident"` in `~/.config/synology-nas-cli/config.json`, then run:
     ```bash
     nas incident fix --only autoblock --yes
     ```
   - Or allow-list `127.0.0.1` directly via the API:
     ```bash
     nas api SYNO.Core.Security.AutoBlock.Rules create --version 1 type=allow block_days=0 overwrite=true 'ip=["127.0.0.1"]' --allow-write
     ```
2. **For Tailscale TUN mode (`100.64.0.0/10`):**
   - Include `"100.64.0.0/10"` in `allowed_networks` in `config.json` (or pass `--allowed-network 100.64.0.0/10` to `nas setup`) before running `nas incident fix --only firewall,autoblock --yes`.
3. **For a reverse proxy:**
   - Add the reverse proxy's internal IP address to `Control Panel > Security > Protection > Allow/Block List > Allow List` (`控制台 > 安全性 > 保護 > 允許/封鎖清單 > 允許清單`) ([Synology DSM Protection Help](https://kb.synology.com/en-global/DSM/help/DSM/AdminCenter/connection_security_protection?version=7)).

---

## 3. Immutable snapshots (WORM) not offered on some models — or silently stopping scheduled snapshots

### Symptoms

- The **Immutable snapshots** (WriteOnce / WORM) checkbox is missing in `Snapshot Replication > Snapshots > Settings` (`Snapshot Replication > 快照 > 設定`), or appears only under `Replication > Schedule` ([SpaceRex forum report](https://forums.spacerex.co/t/snapshot-replication-no-immutable-snapshot-option/842)).
- Or `nas incident` reports `snapshot_worm:<share> FAIL` and `nas alert` reports `snapshot_worm_unsupported`: scheduled snapshots for the share have stopped being taken even though the schedule is enabled, with no error in Log Center.

### Cause

- **Model and DSM requirements:** Synology introduced WriteOnce shared folders and Immutable Snapshots in DSM 7.2 ([Synology DSM 7.2 release](https://www.synology.com/en-us/company/news/article/DSM72)), and supports them only on PAS, HD, FS, SA series and 20-series or newer Plus/xs/RS models (such as DS220+, DS920+, DS1520+, DS1621+, DS224+, DS923+, DS925+); 18-series and older Plus models (such as DS918+, DS718+, DS916+, DS218+) and all Value / `j`-series models are not supported ([Synology KB: Which Synology models support WriteOnce and immutable snapshots?](https://kb.synology.com/DSM/tutorial/which_synology_nas_models_support_WriteOnce_and_secure_snapshots)).
- **The silent API trap on unsupported models:** On models whose `SYNO.DisasterRecovery.Retention info` response does not include `worm` in `adv_features`, the DSM UI hides the WORM checkbox, **yet calling `SYNO.DisasterRecovery.Retention set_worm_lock` with `worm_lock_enable=true` over the Web API returns `{"success": true}`**. Once set, scheduled snapshots for that share silently stop executing without logging an error ([`DSM-API-NOTES.md`](DSM-API-NOTES.md#snapshots-snapshot-replication-btrfs-volumes)).
- **Retention rotation:** On any model, a short "keep latest N" retention window can rotate out the last clean snapshots if ransomware encryption goes unnoticed longer than the retention window ([Snapshot retention GFS guide](https://hometechops.com/guides/snapshot-retention-gfs), [CyberQ](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/)).

### Fix

1. **Clear the unsupported WORM lock so scheduled snapshots resume:**
   ```bash
   nas incident fix --only snapshot_worm --ransom-scan --yes
   ```
   Or for a single share via `nas api`:
   ```bash
   nas api SYNO.DisasterRecovery.Retention set_worm_lock --version 1 type=Share name=SHARE worm_lock_enable=false worm_lock_day=7 --allow-write
   ```
2. **Use GFS retention and 3-2-1 off-site backups:**
   - Configure Grandfather-Father-Son (GFS) retention rules (`Snapshot Replication > Snapshots > select share > Settings > Retention` / `保留原則`) and maintain an off-site or offline versioned Hyper Backup copy ([Synology Ransomware Prevention](https://kb.synology.com/en-global/DSM/tutorial/How_can_I_prevent_ransomeware_attacks_on_my_Synology_device)).

---

## 4. Hyper Backup to Google Drive quota errors

### Symptoms

- Hyper Backup tasks backing up to Google Drive fail repeatedly with Google Drive API HTTP `403` (`Rate Limit Exceeded` / `userRateLimitExceeded`), or stall partway through a multi-terabyte initial backup ([Synology Community post 136025](https://community.synology.com/enu/forum/1/post/136025)).
- Upload throughput to Google Drive plateaus around ~15 MB/s ([Synology Community post 153889](https://community.synology.com/enu/forum/1/post/153889)).

### Cause

- Google Workspace and Google Drive enforce a hard per-user upload and copy quota of **750 GB within any rolling 24-hour window** (individual files up to 5 TB already in flight complete, after which all uploads are refused until the 24-hour window resets) ([Google Workspace Admin Help: Storage and upload limits](https://knowledge.workspace.google.com/admin/drive/storage-and-upload-limits-for-google-workspace)).
- Any other tool uploading to the same Google account (such as Cloud Sync, `rclone`, or desktop Google Drive clients) consumes the same 750 GB daily pool ([Synology Community post 136025](https://community.synology.com/enu/forum/1/post/136025)).

### Fix

1. Pause other upload tools (`rclone`, Cloud Sync, desktop sync) sharing the same Google account while the initial Hyper Backup seed runs.
2. Wait up to 24 hours for the Google Drive 750 GB daily upload window to refresh, then resume the Hyper Backup task (`Hyper Backup > select task > Back up now`).
3. For multi-terabyte initial backups, split the backup task across smaller shared-folder selections so each initial run stays under 750 GB per day, or use a dedicated backup storage target without a 750 GB/day cap (Synology C2, S3-compatible storage, or a second Synology NAS running Hyper Backup Vault).

---

## 5. SMB1-only devices losing access after raising the minimum SMB version

### Symptoms

- After running `nas incident fix` (which sets `smb_min_protocol` to SMB2) or upgrading from DSM 6 to DSM 7, legacy network printers/scanners (such as the HP OfficeJet Pro 8600 Plus), older IP cameras, Sonos v1 / media players, or Windows XP machines can no longer connect or scan to SMB shared folders ([Synology KB: I lost access to shared folders via SMB after updating to DSM 7](https://kb.synology.com/en-global/DSM/tutorial/I_cannot_access_shared_folders_from_WinXP_computer), [mysysadmintips HP OfficeJet report](https://www.mysysadmintips.com/hp-officejet-pro-8600-plus-no-longer-scans-to-smb-shares/)).

### Cause

- `nas incident fix` sets DSM's minimum SMB protocol to `SMB2` (`smb_min_protocol=1`), and DSM 7 disables NTLMv1 authentication by default, requiring SMB2+ and NTLMv2 ([Synology SMB / WinXP KB](https://kb.synology.com/en-global/DSM/tutorial/I_cannot_access_shared_folders_from_WinXP_computer)).

### Fix

1. **Preferred (keep SMB1 disabled):**
   - Configure the scanner, printer, or camera to upload via SFTP, FTPS, or WebDAV to a dedicated non-admin DSM user restricted to a single ingest folder, or replace the legacy device ([Synology SMB / WinXP KB](https://kb.synology.com/en-global/DSM/tutorial/I_cannot_access_shared_folders_from_WinXP_computer)).
2. **If you must re-enable SMB1 on an isolated LAN:**
   - In the DSM UI: open `Control Panel > File Services > SMB > Advanced Settings > General` (`控制台 > 檔案服務 > SMB > 進階設定 > 一般`), set **Minimum SMB protocol** to **SMB1**, and if the device also requires NTLMv1, open the **Others** (`其他`) tab and enable **Enable NTLMv1 authentication** ([Synology SMB / WinXP KB](https://kb.synology.com/en-global/DSM/tutorial/I_cannot_access_shared_folders_from_WinXP_computer)).
   - Or via `nas api` (and pass `--skip smb_min_protocol` on future `nas incident fix` runs):
     ```bash
     nas api SYNO.Core.FileServ.SMB set --version 3 smb_min_protocol=0 smb_max_protocol=3 --allow-write
     ```

---

## 6. 2-step verification (2FA) lockout

### Symptoms

- `nas` exits with code `4` and DSM auth error `403` (2-step verification code required), `404` (2-step verification code failed), or `406` (2-step verification enforced but not enrolled).
- Or you lost your phone/authenticator app or TOTP codes are rejected even when typed immediately.

### Cause

- **For CLI / agent runs (`403`):** The account has 2FA enabled on DSM, and neither a trusted-device token nor an OTP source (`--otp-code`, `credentials.otp_command`, or 1Password OTP) was provided.
- **Rejected codes (`404`):** The NAS's system clock has drifted out of sync with NTP, causing time-based one-time passwords (TOTP) to fail ([Synology KB: How do I reset 2-step verification?](https://kb.synology.com/en-global/DSM/tutorial/How_do_I_reset_2_step_verification)).
- **Lost authenticator device:** The phone or hardware token was lost or reset.

### Fix

1. **For `nas` CLI logins (when you have your authenticator):**
   - Pass the current 6-digit code once with `--trust-device` so DSM issues a persistent device token (`~/.config/synology-nas-cli/device-token.json`, mode `0600`):
     ```bash
     nas setup --otp-code 123456 --trust-device
     # or after setup:
     nas login --trust-device
     ```
   - Or configure automatic OTP retrieval in `config.json` via 1Password (`op_password` on an item that also holds the TOTP secret) or `credentials.otp_command` (e.g. `oathtool --totp -b SECRET`).
2. **If valid TOTP codes are rejected (`404` clock skew):**
   - Check clock skew with `nas doctor` (`clock` check).
   - In DSM, open `Control Panel > Regional Options > Time` (`控制台 > 地區選項 > 時間`), select **Synchronize with NTP server**, and click **Update Now** ([Synology 2FA reset KB](https://kb.synology.com/en-global/DSM/tutorial/How_do_I_reset_2_step_verification)).
3. **If you lost your 2FA device:**
   - **If another administrator account exists:** Sign in with the other administrator account, open `Control Panel > User & Group > User > select locked user > Edit > Info` (`控制台 > 使用者與群組 > 使用者 > 編輯 > 資訊`), and click **Reset 2-Factor Authentication** ([Synology 2FA reset KB](https://kb.synology.com/en-global/DSM/tutorial/How_do_I_reset_2_step_verification)).
   - **If you are the only administrator:** Perform a **Mode 1 reset** (hold the rear `RESET` button ~4 seconds until one beep). Mode 1 re-enables the built-in `admin` account with 2FA disabled; sign in as `admin`, reset 2FA on your administrator account in `Control Panel > User & Group`, and then re-disable `admin` and re-enable your firewall and AutoBlock rules (`nas incident fix --yes`) ([Synology 2FA reset KB](https://kb.synology.com/en-global/DSM/tutorial/How_do_I_reset_2_step_verification), [Synology reset KB](https://kb.synology.com/en-global/DSM/tutorial/How_to_reset_my_Synology_NAS_7)).

---

## 7. DSM Web API errors 105 / 106 / 107 / 119 / 400 / 403 / 404 / 407 (and 498 / 499)

### Symptoms

- A `nas` command or raw `nas api` call returns a DSM error code (`105`, `106`, `107`, `119`, `400`, `403`, `404`, `407`, `498`, `499`).

### Cause and Fix by error code

Error codes come from two layers: common session/dispatcher codes (`100`–`150`) and API-specific codes (`400`+), where `SYNO.API.Auth` and `SYNO.FileStation` assign different meanings to the same `4xx` numbers ([Synology DSM Login Web API Guide PDF](https://global.download.synology.com/download/Document/Software/DeveloperGuide/Os/DSM/All/enu/DSM_Login_Web_API_Guide_enu.pdf), [N4S4/synology-api `error_codes.py`](https://raw.githubusercontent.com/N4S4/synology-api/master/synology_api/error_codes.py), [N4S4/synology-api issue #118](https://github.com/n4s4/synology-api/issues/118), [`DSM-API-NOTES.md`](DSM-API-NOTES.md)).

| Code | API context | Cause | Fix |
|---|---|---|---|
| `105` | Common / any API | Logged-in session lacks administrator privilege, requires a `SYNO.Core.User.PasswordConfirm` token, or called `SYNO.Core.User set` (which returns `105` from any password session even for an admin) ([kwent/syno #15](https://github.com/kwent/syno/issues/15)) | Sign in with an account in the `administrators` group (`nas doctor` checks `capabilities`). To disable `admin`, use `nas incident fix --only admin_account` (which runs `/usr/syno/bin/synowebapi --exec` inside a temporary root Task Scheduler task). To change your own password, use `SYNO.Core.NormalUser set` v2 or `nas incident fix --rotate-password`. |
| `106` | Common | Session timed out | `nas` automatically re-authenticates when using a cached session (`nas login`); if using `NAS_SID`, obtain a fresh SID. |
| `107` | Common | Session interrupted by a duplicate login | `nas` automatically renews cached sessions; avoid sharing one `NAS_SID` across incompatible settings. |
| `119` | Common | Invalid session / SID not found, or `SynoToken` was not passed in the URL query string (`entry.cgi?SynoToken=...`) ([administrator.de thread](https://administrator.de/forum/synology-calendar-api-error-119-667427.html)) | `nas` always passes `SynoToken` in the URL query string and renews expired cached sessions automatically. If `NAS_SID` + `NAS_SYNOTOKEN` were pasted from a browser tab that logged out, clear those environment variables or copy a fresh pair. |
| `400` | `SYNO.API.Auth` | No such account or wrong password (counts as 1 failed attempt toward AutoBlock) | Fix the username or password in your credential source (`nas config show`) before running another command. `nas` never retries a failed password. |
| `400` | `SYNO.FileStation.*` | Invalid parameter of file operation | Check path formatting (shares start with `/sharename`). |
| `403` | `SYNO.API.Auth` | 2-step verification (OTP) code required | Run `nas setup --otp-code CODE --trust-device` or `nas login --trust-device`, or configure `credentials.otp_command` / 1Password OTP. |
| `403` | `SYNO.FileStation.*` | Current user does not have permission for the requested file operation ([N4S4/synology-api #118](https://github.com/n4s4/synology-api/issues/118)) | Grant the account Read/Write permission on the shared folder (`deploy.stage_dir`) in `Control Panel > Shared Folder > Edit > Permissions`. |
| `404` | `SYNO.API.Auth` | 2-step verification code failed (wrong code or NAS clock drift) | Check NTP synchronization on the NAS (`nas doctor`) and verify the 6-digit TOTP code. |
| `407` | `SYNO.API.Auth` | Source IP address is blocked by AutoBlock (CLI exit code `5`) | Unblock the IP from another device in `Control Panel > Security > Protection > Allow/Block List` or use the Mode 1 reset path above. |
| `407` | `SYNO.FileStation.*` | Operation not permitted on the target filesystem path ([N4S4/synology-api #118](https://github.com/n4s4/synology-api/issues/118)) | Check shared folder permissions and Read-Only / WriteOnce state. |
| `498` / `499` | `SYNO.API.Auth` | DSM is currently installing an update (`498`) or running post-upgrade startup tasks (`499`, CLI exit code `6`) | Run `nas upgrade --wait-only` to poll `SYNO.Core.Desktop.SessionData` until `dsm_upgrade_all_done` is true. |

---

## 8. The "DSM says up to date but is not" case

### Symptoms

- `Control Panel > Update & Restore > DSM Update` (`控制台 > 更新與還原 > 系統更新`) displays **"Your DSM version is up to date"**, yet `nas status`, `nas doctor`, or `nas incident` reports `dsm_version FAIL` (for example, the unit is on `DSM 7.1.1-42962 Update 9` or an older `7.2.x` build missing the SA-26:13 patch).

### Cause

- DSM's built-in update checker only checks for incremental updates pushed to the device's current major/minor branch and staged rollout wave; it does not automatically cross branch boundaries (such as DSM 7.1 → 7.2.2 or 7.3/7.4), and branches like DSM 7.1 receive no SA-26:13 fix ([Synology-SA-26:13](https://www.synology.com/en-global/security/advisory/Synology_SA_26_13), [CyberQ](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/)). This same "no updates available" UI behavior affected DSM 4.3 victims during the 2014 SynoLocker campaign ([Synology SynoLocker advisory](https://www.synology.com/en-uk/security/advisory/SynoLocker)).

### Fix

1. **Check the real build and `smallfixnumber`:**
   ```bash
   nas status
   nas upgrade --dry-run
   ```
   Or over SSH on the NAS:
   ```sh
   cat /etc.defaults/VERSION
   ```
   Compare `majorversion`, `minorversion`, `buildnumber`, and `smallfixnumber` against the SA-26:13 fixed builds (`7.4-90075`, `7.3.2-86009-4`, `7.2.2-72806-9`, `7.2.1-69057-12`) ([itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/)).
2. **Download and install the latest `.pat` with `nas upgrade`:**
   ```bash
   nas upgrade                         # downloads the newest .pat from Synology's download API and runs PreCheck
                                       # (with NAS_YES=1 or config assume_yes: installs and reboots, as --yes)
   nas upgrade --yes                   # downloads, runs PreCheck, installs, and reboots
   ```
   Or download the `.pat` file manually from [Synology Download Center](https://www.synology.com/en-global/support/download) and apply it via `Control Panel > Update & Restore > DSM Update > Manual DSM Update` (`手動更新 DSM`) or `nas upgrade --pat /path/to/DSM.pat --yes`.

---

## 9. TLS certificate pin changes (`nas trust`)

### Symptoms

- `nas` exits with code `7` and prints:
  `nas: the TLS certificate of https://192.0.2.10:5001 changed (pinned sha256 ..., got ...). If you replaced the DSM certificate, run: nas trust --reset https://192.0.2.10:5001`

### Cause

- When `tls.verify` is `false` (the default, because DSM ships with a self-signed certificate), `nas` uses Trust-On-First-Use (TOFU): on the first connection to an origin it records the certificate's SHA-256 fingerprint in `~/.config/synology-nas-cli/known-certs.json` (mode `0600`) and rejects any later connection that presents a different certificate.
- A fingerprint change happens when DSM renews a Let's Encrypt certificate, when you import or replace a certificate in `Control Panel > Security > Certificate` (`控制台 > 安全性 > 憑證`), when you switch to a different NAS on the same IP, or when something intercepts the TLS connection.

### Fix

1. **Inspect currently pinned certificates:**
   ```bash
   nas trust
   ```
2. **If you intentionally renewed or replaced the certificate on the NAS, reset the pin for that origin:**
   ```bash
   nas trust --reset https://192.0.2.10:5001
   ```
   The next connection (`nas doctor` or `nas whoami`) will pin the new certificate's SHA-256 fingerprint.
3. **If the NAS uses a valid CA-signed certificate (such as Let's Encrypt on a domain or Tailscale HTTPS cert):**
   - Set `"tls": {"verify": true}` in `config.json` (or run `nas setup --tls verify`) so certificates are validated against the system CA store instead of pinned by SHA-256 fingerprint, avoiding pin resets on routine renewals.
