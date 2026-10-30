# Synology DSM security hardening checklist

A practical hardening checklist for Synology DSM 7 systems, built from Synology security advisories, Synology Knowledge Base guides, CISA, NCSC, and CSA guidance. Every item explains **why** with source links, gives the **DSM web UI path** (in English and 繁體中文), and lists the **`nas` CLI command** that checks or applies it.

## Quick summary table

| # | Area | Check command | Apply command |
|---|---|---|---|
| 1 | DSM version & security patches (SA-26:13, SA-24:20) | `nas status`, `nas doctor`, `nas incident` | `nas upgrade --yes` or `nas incident fix --upgrade --yes` |
| 2 | Vulnerable or unused packages (SA-26:14 PHP2Shell) | `nas inventory`, `nas pkg list`, `nas incident` | `nas incident fix --only packages --yes`, `nas pkg stop ID`, `nas pkg uninstall ID` |
| 3 | Default-deny DSM firewall on all interfaces | `nas net`, `nas exposure`, `nas incident --probe` | `nas incident fix --only firewall --yes` |
| 4 | QuickConnect & router UPnP port forwarding off | `nas services`, `nas incident` | `nas incident fix --only quickconnect,router_port_forwarding --yes` |
| 5 | VPN / Tailscale instead of public port forwards | `nas tailscale status` | `nas tailscale login-url` |
| 6 | Container Manager / Docker port binding hygiene | `nas inventory`, `nas exposure` | Bind container ports to `127.0.0.1` or LAN IP |
| 7 | Deactivate the built-in `admin` account | `nas inventory`, `nas incident` | `nas incident fix --only admin_account --yes` |
| 8 | Strong unique administrator passwords | `nas doctor`, `nas whoami` | `nas incident fix --rotate-password --yes` |
| 9 | 2-step verification (OTP) & hardware security keys | `nas doctor`, `nas inventory` | `nas setup --otp-code CODE --trust-device`, `nas login --trust-device` |
| 10 | AutoBlock & Account Protection | `nas services`, `nas incident` | `nas incident fix --only autoblock --yes` |
| 11 | SMB minimum protocol (SMB2+) & file services (FTP, NFS, SSH) | `nas services`, `nas incident` | `nas incident fix --only smb_min_protocol --yes` |
| 12 | Scheduled Btrfs snapshots, GFS retention & Immutable Snapshots (WORM) | `nas incident`, `nas alert --no-update` | `nas incident fix --only snapshot_worm,snapshots --ransom-scan --yes` |
| 13 | 3-2-1 off-site and offline versioned backups | `nas inventory` | Configure in Hyper Backup |
| 14 | Log Center, Security Advisor & continuous webhook alerts | `nas logs`, `nas alert --no-update` | `nas alert-deploy --test` |

---

## 1. Keep DSM on a supported, patched build (SA-26:13 & SA-24:20)

- **Why:** Pre-authentication remote code execution and arbitrary file read/write flaws in DSM — including CVE-2024-10441 in [Synology-SA-24:20](https://www.synology.com/en-global/security/advisory/Synology_SA_24_20) and CVE-2026-13684 / CVE-2026-13639 in [Synology-SA-26:13](https://www.synology.com/en-global/security/advisory/Synology_SA_26_13) ([CSA Singapore AL-2026-127](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-127/)) — bypass passwords and 2-step verification completely ([Synology C3RB3R statement](https://www.synology.com/en-global/company/news/article/C3RB3R)). Older branches (DSM 7.1 and earlier) receive no SA-26:13 fix, and DSM's automatic updater does not cross major/minor branch boundaries on its own, so a unit on DSM 7.1.1 can display "Your DSM version is up to date" while remaining vulnerable ([Synology DSM Update Help](https://kb.synology.com/zh-tw/DSM/help/DSM/AdminCenter/system_dsmupdate?version=7), [Synology Product Support Status](https://www.synology.com/en-global/products/status?model=DS)).
- **DSM UI path:**
  - English: `Control Panel > Update & Restore > DSM Update`
  - 繁體中文：`控制台 > 更新與還原 > 系統更新`
- **`nas` commands:**
  ```bash
  nas status                          # shows model, build, and SA-26:13 patch verdict
  nas doctor                          # checks dsm_version against SA-26:13
  nas upgrade --dry-run               # checks Synology's download API for a newer .pat
  nas upgrade --yes                   # downloads, runs PreCheck, installs, and reboots
  nas incident fix --upgrade --yes    # runs the upgrade as part of incident remediation
  ```
  Over SSH on the NAS, `cat /etc.defaults/VERSION` shows the exact `buildnumber` and `smallfixnumber` (Update level).

## 2. Update or stop vulnerable and unused packages (SA-26:14 "PHP2Shell")

- **Why:** [Synology-SA-26:14](https://www.synology.com/en-global/security/advisory/Synology_SA_26_14) fixes CVE-2026-109618 and CVE-2026-109619 (CVSS 3.1 9.8) in Synology Calendar (`3.0.4-21435`), MailStation (`30000002.3.19-20333`), and PHP 7.4–8.4 (`7.4.33-0131`, `8.0.30-0122`, `8.1.34-0120`, `8.2.35-0171`, `8.3.36-0051`, `8.4.27-0051`). PHP 7.3 is end-of-life with no fix. Stopping or uninstalling packages you do not use shrinks the exposed web attack surface ([Synology Security Tutorial](https://kb.synology.com/zh-tw/DSM/tutorial/How_to_add_extra_security_to_your_Synology_NAS), [CISA KEV alert](https://www.cisa.gov/news-events/alerts/2026/10/26/cisa-adds-two-known-exploited-vulnerabilities-catalog)). Note that Hyper Backup depends on PHP 7.4 on some setups, so stop or update PHP 7.4 rather than blindly uninstalling it if Hyper Backup is installed ([Dongyun Lab, 2026-10-29](https://dylab.org/archives/1128)).
- **DSM UI path:**
  - English: `Package Center > Installed` (and `Package Center > Settings > Auto-update`)
  - 繁體中文：`套件中心 > 已安裝`（以及 `套件中心 > 設定 > 自動更新`）
- **`nas` commands:**
  ```bash
  nas inventory                       # lists installed packages and flags SA-26:14 versions
  nas pkg list                        # lists all packages with version and running status
  nas incident fix --only packages --yes   # stops running SA-26:14 vulnerable packages
  nas pkg stop PHP7.4                 # stops a specific package
  nas pkg uninstall PHP7.3            # uninstalls an end-of-life package
  ```

## 3. Enable a default-deny DSM firewall on all interfaces

- **Why:** If the NAS dials PPPoE itself, sits in a router DMZ, or holds a global IPv6 address, there is no NAT router protecting it; even on a LAN, a default-deny firewall that only allows your LAN/VPN subnets on the LAN interface prevents unauthorized external connections when a router port forward or UPnP rule is accidentally opened ([Synology Firewall Help](https://kb.synology.com/en-global/DSM/help/DSM/AdminCenter/connection_security_firewall?version=7), [Synology Security Tutorial](https://kb.synology.com/zh-tw/DSM/tutorial/How_to_add_extra_security_to_your_Synology_NAS), [Synology Ransomware Prevention](https://kb.synology.com/en-global/DSM/tutorial/How_can_I_prevent_ransomeware_attacks_on_my_Synology_device), [NSA/CISA Home Network Security Guide](https://media.defense.gov/2023/Feb/22/2003165170/-1/-1/0/CSI_BEST_PRACTICS_FOR_SECURING_YOUR_HOME_NETWORK.PDF)). Put allow rules (such as `100.64.0.0/10` for Tailscale) on the LAN interfaces rather than `global`, because `100.64.0.0/10` is also used by CGNAT ISPs on PPPoE WAN links.
- **DSM UI path:**
  - English: `Control Panel > Security > Firewall > Enable firewall > Edit Rules`
  - 繁體中文：`控制台 > 安全性 > 防火牆 > 啟用防火牆 > 編輯規則`
- **`nas` commands:**
  ```bash
  nas net                             # shows interfaces, PPPoE status, and firewall profile rules
  nas exposure                        # probes LAN and public IP ports from this machine
  nas incident --probe                # audits firewall rules and probes public ports
  nas incident fix --only firewall --yes   # enables firewall, allows this host + allowed_networks on LAN, drops all else
  ```

## 4. Turn off QuickConnect and router UPnP port forwarding

- **Why:** QuickConnect issues TLS certificates that appear in public Certificate Transparency logs, enabling attackers to enumerate millions of `*.quickconnect.to` subdomains and reach DSM through the QuickConnect relay even without port forwarding ([Midnight Blue RISK:STATION](https://www.midnightblue.nl/research/riskstation)). UPnP/NAT-PMP router configuration in DSM (`SYNO.Core.PortForwarding.Rules` and `SYNO.Core.QuickConnect.Upnp`) automatically opens ports on the router ([Synology Security Tutorial](https://kb.synology.com/zh-tw/DSM/tutorial/How_to_add_extra_security_to_your_Synology_NAS), [NSA/CISA Home Network Security Guide](https://media.defense.gov/2023/Feb/22/2003165170/-1/-1/0/CSI_BEST_PRACTICS_FOR_SECURING_YOUR_HOME_NETWORK.PDF)). Also check the router's own administration page to disable UPnP and remove manual port forwards to ports 5000, 5001, 445, 21, 22, 80, and 443.
- **DSM UI path:**
  - English: `Control Panel > External Access > QuickConnect` and `Control Panel > External Access > Router Configuration`
  - 繁體中文：`控制台 > 外部存取 > QuickConnect` 以及 `控制台 > 外部存取 > 路由器設定`
- **`nas` commands:**
  ```bash
  nas services                        # reports QuickConnect and router port-forwarding rules
  nas incident fix --only quickconnect,router_port_forwarding --yes
  ```

## 5. Use a VPN (such as Tailscale) for remote access

- **Why:** Accessing DSM over an encrypted VPN or overlay network (Tailscale, WireGuard, OpenVPN) keeps DSM's login page and file shares completely off the public internet ([Synology Ransomware Prevention](https://kb.synology.com/en-global/DSM/tutorial/How_can_I_prevent_ransomeware_attacks_on_my_Synology_device), [CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide), [Tailscale Synology KB](https://tailscale.com/kb/1131/synology)). On DSM 7, Tailscale runs in userspace networking mode by default and proxies incoming tailnet connections through `127.0.0.1` ([Tailscale localhost architecture](https://forum.tailscale.com/t/why-does-localhost-work/4240)); see [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) for how this interacts with AutoBlock and TUN mode.
- **DSM UI path:**
  - English: `Package Center > Tailscale` (or `Control Panel > Network > Network Interface > Create VPN Profile`)
  - 繁體中文：`套件中心 > Tailscale`（或 `控制台 > 網路 > 網路介面 > 新增 VPN 設定檔`）
- **`nas` commands:**
  ```bash
  nas tailscale status                # shows Tailscale version, state, tailnet IPs, and key expiry
  nas tailscale login-url             # requests a fresh login/reauthentication URL from the Tailscale package
  ```

## 6. Audit Container Manager (Docker) port bindings and firewall interaction

- **Why:** On Linux and DSM, Docker / Container Manager inserts rules into the `DOCKER` `iptables` chain that can publish container ports ahead of host input firewall filters ([Docker packet filtering and firewalls](https://docs.docker.com/engine/network/packet-filtering-firewalls/), [Synology Docker firewall notes](https://gist.github.com/pedrolamas/db809a2b9112166da4a2dbf8e3a72ae9)). In addition, containers running with `network_mode: host` or publishing unauthenticated internal APIs (such as `go2rtc`'s port `1984` API, or unpatched GitLab/Confluence containers) expose those services directly on the NAS's interfaces ([go2rtc internal API docs](https://go2rtc.org/internal/api/), [Guru3d](https://www.guru3d.com/story/synology-nas-devices-hit-by-l0ck3d-ransomware-campaign/)). Bind container ports to `127.0.0.1:PORT:PORT` or the LAN IP rather than `0.0.0.0:PORT:PORT` when external access is not needed.
- **DSM UI path:**
  - English: `Container Manager > Container` / `Container Manager > Project`
  - 繁體中文：`Container Manager > 容器`／`Container Manager > 專案`
- **`nas` commands:**
  ```bash
  nas inventory                       # lists running and stopped Docker containers and projects
  nas exposure                        # probes common ports on LAN and public IPs
  ```

## 7. Deactivate the built-in `admin` account

- **Why:** Botnets (such as the July 2019 brute-force wave and the 2021 StealthWorker campaign) target the default `admin` username first ([Synology 2019 ransomware release](https://www.synology.com/en-global/company/news/article/2019JulyRansomware), [Synology BruteForce release](https://www.synology.com/en-global/company/news/article/BruteForce), [Synology Account Security Help](https://kb.synology.com/zh-tw/DSM/help/DSM/AdminCenter/connection_security_account?version=7)). Create a dedicated administrator account with a non-default name, transfer ownership of scheduled tasks and shared data, and deactivate `admin` (do not rename `admin` or `/homes/admin`) ([Synology KB: duplicate admin data and settings](https://kb.synology.com/en-in/DSM/tutorial/How_to_duplicate_admin_data_and_settings), [Synology KB: services affected by disabling admin](https://kb.synology.com/en-global/DSM/tutorial/services_affected_by_disable_admin)).
- **DSM UI path:**
  - English: `Control Panel > User & Group > User > select admin > Edit > General > Disable this account`
  - 繁體中文：`控制台 > 使用者與群組 > 使用者 > 選擇 admin > 編輯 > 一般 > 停用此帳號`
- **`nas` commands:**
  ```bash
  nas inventory                       # lists accounts, admin group membership, and enabled/disabled status
  nas incident fix --only admin_account --yes   # verifies another admin exists and disables `admin`
  ```

## 8. Enforce strong unique passwords and password rotation

- **Why:** Credential stuffing and dictionary attacks succeed when NAS administrator accounts reuse passwords from breached services or use short passwords ([Synology Security Tutorial](https://kb.synology.com/zh-tw/DSM/tutorial/How_to_add_extra_security_to_your_Synology_NAS), [Synology BruteForce release](https://www.synology.com/en-global/company/news/article/BruteForce), [Synology Account Security Help](https://kb.synology.com/zh-tw/DSM/help/DSM/AdminCenter/connection_security_account?version=7)). Store credentials in a password manager (1Password or OS keychain) rather than plain-text scripts or environment variables.
- **DSM UI path:**
  - English: `Control Panel > User & Group > Advanced > Password Settings` and `Personal > Account`
  - 繁體中文：`控制台 > 使用者與群組 > 進階設定 > 密碼設定` 以及 `個人 > 帳號`
- **`nas` commands:**
  ```bash
  nas incident fix --rotate-password --yes   # generates a 24-char random password, updates 1Password/keychain first, then DSM
  ```

## 9. Enable 2-step verification (OTP) and hardware security keys

- **Why:** 2-step verification (TOTP authenticator app or hardware security key / FIDO2 passkey) prevents an attacker who phishes or guesses a password from signing in to DSM ([Synology 2FA Help](https://kb.synology.com/zh-tw/DSM/help/DSM/SecureSignIn/2factor_authentication?version=7), [Synology Hardware Security Key Help](https://kb.synology.com/en-global/DSM/help/DSM/SecureSignIn/hardware_security_key?version=7), [Synology Security Tutorial](https://kb.synology.com/zh-tw/DSM/tutorial/How_to_add_extra_security_to_your_Synology_NAS), [Synology 2019 ransomware release](https://www.synology.com/en-global/company/news/article/2019JulyRansomware)). Ensure NTP time synchronization is enabled in `Control Panel > Regional Options > Time` (`控制台 > 地區選項 > 時間`) so TOTP codes stay aligned.
- **DSM UI path:**
  - English: `Personal > Account > 2-Factor Authentication` and `Control Panel > Security > Account > 2-Factor Authentication`
  - 繁體中文：`個人 > 帳號 > 兩步驟驗證` 以及 `控制台 > 安全性 > 帳號 > 兩步驟驗證`
- **`nas` commands:**
  ```bash
  nas doctor                          # checks two_factor status and clock skew
  nas inventory                       # shows 2FA enrollment per user
  nas setup --otp-code 123456 --trust-device
  nas login --trust-device            # stores DSM's trusted-device token in ~/.config/synology-nas-cli/device-token.json
  ```

## 10. Enable AutoBlock and Account Protection

- **Why:** AutoBlock blocks source IP addresses that exceed a threshold of failed login attempts (default: 10 attempts within 5 minutes) across DSM, SSH, SMB, FTP, and Rsync, stopping dictionary attacks ([Synology Protection Help](https://kb.synology.com/en-global/DSM/help/DSM/AdminCenter/connection_security_protection?version=7), [Synology BruteForce release](https://www.synology.com/en-global/company/news/article/BruteForce), [Synology 2019 ransomware release](https://www.synology.com/en-global/company/news/article/2019JulyRansomware)). Always add your LAN subnet (and your reverse proxy IP, or `127.0.0.1` via `incident.autoblock_allow_loopback: true` when using Tailscale userspace mode) to the Allow List so a mistyped password does not lock out all users ([Synology Protection Help](https://kb.synology.com/en-global/DSM/help/DSM/AdminCenter/connection_security_protection?version=7), [Tailscale localhost architecture](https://forum.tailscale.com/t/why-does-localhost-work/4240)).
- **DSM UI path:**
  - English: `Control Panel > Security > Protection > Auto Block` and `Allow/Block List` and `Account Protection`
  - 繁體中文：`控制台 > 安全性 > 保護 > 自動封鎖`、`允許/封鎖清單` 以及 `帳號保護`
- **`nas` commands:**
  ```bash
  nas services                        # shows AutoBlock status, threshold, and expiration
  nas incident fix --only autoblock --yes   # enables AutoBlock (10 attempts / 5 min) and allow-lists this host + allowed_networks
  ```

## 11. Disable SMB1 and harden file services (SMB, FTP, NFS, SSH)

- **Why:** SMB1 and NTLMv1 are legacy protocols susceptible to lateral movement and credential-relay attacks ([Synology SMB / WinXP KB](https://kb.synology.com/en-global/DSM/tutorial/I_cannot_access_shared_folders_from_WinXP_computer), [CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide)). Disable unencrypted FTP (use SFTP or FTPS only if needed) ([Synology FTP Help](https://kb.synology.com/zh-tw/DSM/help/DSM/AdminCenter/file_ftp_setting?version=7)), scope NFS permissions to specific client IPs and read-only where possible ([Synology NFS Help](https://kb.synology.com/en-global/DSM/help/DSM/AdminCenter/file_winmacnfs_nfs?version=7)), and keep SSH/Telnet disabled when not actively administering the box ([Synology Security Tutorial](https://kb.synology.com/zh-tw/DSM/tutorial/How_to_add_extra_security_to_your_Synology_NAS)).
- **DSM UI path:**
  - English:
    - SMB: `Control Panel > File Services > SMB > Advanced Settings > Minimum SMB protocol`
    - FTP: `Control Panel > File Services > FTP`
    - NFS: `Control Panel > File Services > NFS` and `Control Panel > Shared Folder > Edit > NFS Permissions`
    - SSH/Telnet: `Control Panel > Terminal & SNMP > Terminal`
  - 繁體中文：
    - SMB：`控制台 > 檔案服務 > SMB > 進階設定 > 最低 SMB 通訊協定`
    - FTP：`控制台 > 檔案服務 > FTP`
    - NFS：`控制台 > 檔案服務 > NFS` 以及 `控制台 > 共用資料夾 > 編輯 > NFS 權限`
    - SSH/Telnet：`控制台 > 終端機 & SNMP > 終端機`
- **`nas` commands:**
  ```bash
  nas services                        # reports SSH, Telnet, FTP, SMB min/max protocol, AFP, NFS, rsync
  nas incident fix --only smb_min_protocol --yes   # sets smb_min_protocol=1 (SMB2) and smb_max_protocol=3 (SMB3)
  ```

## 12. Configure scheduled Btrfs snapshots, GFS retention, and Immutable Snapshots (WORM)

- **Why:** Read-only Btrfs snapshots allow rapid recovery of encrypted shared folders ([Synology Ransomware Prevention](https://kb.synology.com/en-global/DSM/tutorial/How_can_I_prevent_ransomeware_attacks_on_my_Synology_device), [Synology 2019 ransomware release](https://www.synology.com/en-global/company/news/article/2019JulyRansomware), [CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide)). Use Grandfather-Father-Son (GFS) tiered retention (hourly/daily/weekly/monthly) so frequent snapshots do not rotate out all clean versions before an infection is noticed ([Snapshot retention GFS guide](https://hometechops.com/guides/snapshot-retention-gfs)). On models that support WriteOnce and Immutable Snapshots (DSM 7.2+ on 20-series and newer Plus/xs/RS, PAS, HD, FS, and SA models), enable Immutable Snapshots so even a compromised administrator credential cannot delete them during the protection period ([Synology WriteOnce & Immutable Snapshots KB](https://kb.synology.com/en-global/DSM/tutorial/which_synology_nas_models_support_WriteOnce_and_secure_snapshots)). On older models without `worm` in `SYNO.DisasterRecovery.Retention info`, do not enable `set_worm_lock` via the API, because DSM accepts the setting and then silently stops taking scheduled snapshots ([`DSM-API-NOTES.md`](DSM-API-NOTES.md#snapshots-snapshot-replication-btrfs-volumes)).
- **DSM UI path:**
  - English: `Snapshot Replication > Snapshots > select shared folder > Settings > Schedule` and `Retention`
  - 繁體中文：`Snapshot Replication > 快照 > 選擇共用資料夾 > 設定 > 排程` 與 `保留原則`
- **`nas` commands:**
  ```bash
  nas incident                        # checks snapshot_schedule:<share> and snapshot_worm:<share> on every share
  nas incident fix --only snapshot_worm,snapshots --ransom-scan --yes
  ```

## 13. Maintain 3-2-1 off-site and offline versioned backups

- **Why:** Btrfs snapshots reside on the same storage pool as the live data, and permanently connected USB drives or non-versioned sync folders are encrypted alongside shares during an attack ([Synology Ransomware Prevention](https://kb.synology.com/en-global/DSM/tutorial/How_can_I_prevent_ransomeware_attacks_on_my_Synology_device), [Synology Ransomware Recovery KB](https://kb.synology.com/en-global/DSM/tutorial/What_to_do_when_NAS_attacked_by_ransomware), [CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide)). Follow the 3-2-1 backup principle with multi-version Hyper Backup tasks to an isolated remote NAS, object storage with Object Lock, or cloud storage that cannot be deleted from the source NAS, plus an offline (air-gapped) disk disconnected when backups finish ([NCSC principles for ransomware-resistant cloud backups](https://www.ncsc.gov.uk/guidance/principles-for-ransomware-resistant-cloud-backups)).
- **DSM UI path:**
  - English: `Hyper Backup > Create > Data backup task` (and `Snapshot Replication > Replication`)
  - 繁體中文：`Hyper Backup > 新增 > 資料備份任務`（以及 `Snapshot Replication > 複寫`）
- **`nas` commands:**
  ```bash
  nas inventory                       # verifies HyperBackup and SnapshotReplication package status and scheduled tasks
  ```

## 14. Run Security Advisor, Log Center, and continuous monitoring (`nas alert-deploy`)

- **Why:** Security Advisor scans DSM settings for weak configurations ([Synology Security Advisor Help](https://kb.synology.com/en-af/DSM/help/DSM/SecurityScan/securityscan_overview?version=7), [Synology Security Tutorial](https://kb.synology.com/zh-tw/DSM/tutorial/How_to_add_extra_security_to_your_Synology_NAS), [Marius Hosting guide](https://mariushosting.com/how-to-protect-and-secure-your-synology-nas-from-attacks/), [IT-Connect C3RB3R guide](https://www.it-connect.tech/c3rb3r-ransomware-is-hitting-synology-nas-devices-how-to-protect-yours/)), and Log Center retains connection logs (`SYNO.Core.SyslogClient.Log` holds roughly 10,000 recent entries before rotating, so forwarding or frequent polling prevents brute-force noise from overwriting earlier events) ([Synology Log Center Help](https://kb.synology.com/zh-tw/DSM/help/LogCenter/logcenter_client?version=7)). `nas alert` and `nas alert-deploy` add continuous 10-minute checks for firewall state, unpatched DSM, external sign-ins, failed sign-in spikes, stale snapshots, the unsupported-model WORM trap, and disk/UPS health ([`ALERTS.md`](ALERTS.md)).
- **DSM UI path:**
  - English: `Security Advisor > Overview`, `Log Center > Logs`, and `Control Panel > Notification > Webhooks / Email / Push Service`
  - 繁體中文：`安全諮詢中心 > 總覽`、`日誌中心 > 日誌` 以及 `控制台 > 通知設定 > Webhook / 電子郵件 / 推播服務`
- **`nas` commands:**
  ```bash
  nas logs --since "2026-10-30 00:00" --top 5
  nas alert --no-update
  nas alert-deploy --test             # installs 10-minute root monitoring + DSM notification webhook
  ```

---

## Source index

1. `[S1]` [Synology KB: How to add extra security to your Synology NAS (繁體中文)](https://kb.synology.com/zh-tw/DSM/tutorial/How_to_add_extra_security_to_your_Synology_NAS)
2. `[S2]` [Synology KB: How can I prevent ransomware attacks on my Synology device?](https://kb.synology.com/en-global/DSM/tutorial/How_can_I_prevent_ransomeware_attacks_on_my_Synology_device)
3. `[S3]` [Synology News: Synology urges users to update DSM following ransomware attacks on outdated DSM versions](https://www.synology.com/en-global/company/news/article/C3RB3R)
4. `[S4]` [Synology News: Synology Investigates Ongoing Brute-Force Attacks From Botnet (2021)](https://www.synology.com/en-global/company/news/article/BruteForce)
5. `[S5]` [Synology News: Synology Urges All Users to Take Immediate Action to Protect Data from Ransomware Attack (2019)](https://www.synology.com/en-global/company/news/article/2019JulyRansomware)
6. `[S6]` [Synology-SA-26:13 DSM Security Advisory](https://www.synology.com/en-global/security/advisory/Synology_SA_26_13)
7. `[S7]` [Synology-SA-26:14 PHP2Shell Security Advisory](https://www.synology.com/en-global/security/advisory/Synology_SA_26_14)
8. `[S8]` [Synology DSM Help: Account Security (繁體中文)](https://kb.synology.com/zh-tw/DSM/help/DSM/AdminCenter/connection_security_account?version=7)
9. `[S9]` [Synology DSM Help: Protection (Auto Block & Account Protection)](https://kb.synology.com/en-global/DSM/help/DSM/AdminCenter/connection_security_protection?version=7)
10. `[S10]` [Synology DSM Help: Firewall](https://kb.synology.com/en-global/DSM/help/DSM/AdminCenter/connection_security_firewall?version=7)
11. `[S11]` [Synology DSM Help: 2-Factor Authentication (繁體中文)](https://kb.synology.com/zh-tw/DSM/help/DSM/SecureSignIn/2factor_authentication?version=7)
12. `[S12]` [Synology DSM Help: DSM Update (繁體中文)](https://kb.synology.com/zh-tw/DSM/help/DSM/AdminCenter/system_dsmupdate?version=7)
13. `[S13]` [Synology DSM Help: FTP Settings (繁體中文)](https://kb.synology.com/zh-tw/DSM/help/DSM/AdminCenter/file_ftp_setting?version=7)
14. `[S14]` [Synology DSM Help: Log Center (繁體中文)](https://kb.synology.com/zh-tw/DSM/help/LogCenter/logcenter_client?version=7)
15. `[S15]` [Synology DSM Help: NFS Settings](https://kb.synology.com/en-global/DSM/help/DSM/AdminCenter/file_winmacnfs_nfs?version=7)
16. `[S16]` [Synology KB: Which Synology NAS models support WriteOnce and immutable snapshots?](https://kb.synology.com/en-global/DSM/tutorial/which_synology_nas_models_support_WriteOnce_and_secure_snapshots)
17. `[S17]` [Synology KB: My Synology NAS was attacked by ransomware. What can I do?](https://kb.synology.com/en-global/DSM/tutorial/What_to_do_when_NAS_attacked_by_ransomware)
18. `[S18]` [Synology DSM Help: Security Advisor Overview](https://kb.synology.com/en-af/DSM/help/DSM/SecurityScan/securityscan_overview?version=7)
19. `[S19]` [Synology Product Support Status](https://www.synology.com/en-global/products/status?model=DS)
20. `[S20]` [CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide)
21. `[S21]` [UK NCSC: Principles for ransomware-resistant cloud backups](https://www.ncsc.gov.uk/guidance/principles-for-ransomware-resistant-cloud-backups)
22. `[S22]` [NSA/CISA Cybersecurity Information Sheet: Best Practices for Securing Your Home Network (PDF)](https://media.defense.gov/2023/Feb/22/2003165170/-1/-1/0/CSI_BEST_PRACTICS_FOR_SECURING_YOUR_HOME_NETWORK.PDF)
23. `[S23]` [Docker Docs: Packet filtering and firewalls](https://docs.docker.com/engine/network/packet-filtering-firewalls/)
24. `[S24]` [Synology Docker iptables firewall notes (pedrolamas)](https://gist.github.com/pedrolamas/db809a2b9112166da4a2dbf8e3a72ae9)
25. `[S25]` [go2rtc Internal API documentation](https://go2rtc.org/internal/api/)
26. `[S26]` [Tailscale Forum: Why does localhost work?](https://forum.tailscale.com/t/why-does-localhost-work/4240)
27. `[S27]` [Marius Hosting: How to Protect and Secure Your Synology NAS From Attacks](https://mariushosting.com/how-to-protect-and-secure-your-synology-nas-from-attacks/)
28. `[S28]` [IT-Connect: C3RB3R ransomware is hitting Synology NAS devices — how to protect yours](https://www.it-connect.tech/c3rb3r-ransomware-is-hitting-synology-nas-devices-how-to-protect-yours/)
29. `[S29]` [CSA Singapore Alert AL-2026-127: Critical Vulnerabilities in Synology Products](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-127/)
30. `[S30]` [Synology DSM Help: Hardware Security Key](https://kb.synology.com/en-global/DSM/help/DSM/SecureSignIn/hardware_security_key?version=7)
