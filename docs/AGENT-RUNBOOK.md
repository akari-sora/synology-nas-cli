# Agent runbook

The sequence an agent follows from a fresh machine to a hardened NAS. Every command takes `--json` (anywhere on the line) and `--no-input` (prompts answer with exit code 3 instead of waiting). Exit codes: [EXIT-CODES.md](EXIT-CODES.md). Output schemas: [`schemas/`](../schemas/). The same steps exist as MCP tools ([MCP.md](MCP.md)): `setup`, `doctor`, `incident_audit`, `incident_fix`.

## Step 0: install

```bash
git clone <repository URL> synology-nas-cli && cd synology-nas-cli
./bin/nas --version                     # exit 0; needs Python 3.8+
# or, as a package with a `nas` command:
pip install git+<repository URL>        # or: pip install <release archive URL>
```

## Step 1: what the human provides

Ask once, together:

| Value | Question to relay | Flag |
|---|---|---|
| DSM address | What is the NAS's DSM address, for example https://192.168.0.10:5001? | `--origin URL` (repeat for a VPN/Tailscale address) |
| Account | Which DSM account should the tool sign in with (an administrator account)? | `--user NAME` |
| Password source | Where does the DSM password come from: a 1Password reference (op://vault/item/field), a command that prints it, or should it be stored in this computer's keychain? | `--password-source op:op://V/I/password` / `command:CMD` / `keychain` (+ `--save-to-keychain --password-stdin`, password on stdin) / `env` (`NAS_PASSWORD`) |
| LAN range | Which network(s) should keep access to the NAS after the firewall is turned on, for example 192.168.0.0/24? | `--allowed-network CIDR` (repeatable) |
| Staging folder (for `--deep`, `alert-deploy`) | Which shared folder can hold a temporary file, for example /docker? | `--stage-dir /SHARE/.nas-cli-deploy` |

## Step 2: setup

```bash
nas setup --json --no-input --origin URL --user USER --password-source SOURCE --allowed-network CIDR --stage-dir PATH
```

| Exit | JSON | Next |
|---|---|---|
| 0 | `{"config", "written": true, "origin", "account", "credentials", "tls": {"mode", "sha256"}, "login": "ok", "dsm", "next_steps"}` | Step 3 |
| 3 | `{"missing": [{"field", "why", "ask_user"}], "config"}` | Relay every `ask_user`, run Step 2 again with the answers as flags. `field: otp`: run again with `--otp-code CODE --trust-device` |
| 4 | `{"login": "failed: DSM login failed: code 400 ..."}` | One attempt was made. Ask the human to correct the password source, then Step 2 again |
| 5 | AutoBlock (407) | Ask the human to remove this computer's address in Control Panel > Security > Protection > Allow/Block List (from another device), then Step 2 again |
| 6 | NAS unreachable / not ready | Ask the human whether the NAS is on and this computer is on its LAN or VPN |
| 7 | certificate changed | Ask the human whether the DSM certificate was replaced; if yes `nas trust --reset ORIGIN`, then Step 2 again |

The password is never written to the config; the config file is mode 600 and holds only the source.

## Step 3: doctor

```bash
nas doctor --json
```

`{"checks": [{"name", "status": "ok|warn|fail|skip", "detail", "next_step"}], "ok"}`; exit 0 when no check is `fail`. Checks: `config`, `credentials`, `origin`, `tls`, `login`, `dsm_version`, `two_factor`, `capabilities`, `clock`. For each `fail`, run its `next_step` (a command) or relay it (a question), then run Step 3 again.

## Step 4: audit

```bash
nas incident --json                     # add --probe (public port test) and --scan (ransom-note search, minutes)
```

`{"items": [{"id", "status": "PASS|WARN|FAIL|SKIP", "detail", "hint", "fix"}], "summary"}`; exit 0 without FAIL, 1 with FAIL. Items with `fix` set are what Step 5 changes. If `ransomware_files` or `ioc_*` is FAIL, follow [INCIDENT-C3RB3R.md](INCIDENT-C3RB3R.md) (isolate, keep evidence, restore) before Step 5.

## Step 5: plan, show it, apply

```bash
nas incident fix --dry-run --json --ransom-scan        # the plan; --ransom-scan also allows the snapshot fixes
```

`{"before": [...], "plan": [{"fix", "target", "before", "after", "calls", "note", "refused"}]}`. Show the human each plan entry (`target: before -> after`, `note`). An entry with `refused` names the flag that applies it (`--force-firewall`, `--force-admin`, `--i-know-snapshots-may-rotate`, or `--force` for all).

```bash
nas incident fix --yes --json --ransom-scan [--force-firewall] [--force-admin] [--upgrade] [--rotate-password]
```

`{"before", "plan", "results": [{"fix", "target", "ok", "now"}], "after": [...]}`; exit 0 when every change was applied and read back and no FAIL is left. `--upgrade` installs the newest DSM (the NAS reboots, DSM answers exit 6 until it is back). `--rotate-password` writes a new random password to the 1Password item or keychain entry and changes it in DSM. `NAS_YES=1` or `assume_yes: true` in the config is the same as `--yes` for every command; `nas mcp --auto-confirm` the same for the MCP tools.

If the firewall result is `ok: false`, its `now` text lists the ways back in: another computer on the NAS's LAN, Synology Assistant / find.synology.com, a Tailscale device (userspace mode reaches DSM as 127.0.0.1), or the RESET button (mode 1) at the NAS (a physical step for the human).

## Step 6 (optional): indicators of compromise

```bash
nas incident --deep --json
```

Adds `exploit_attempts_logs`, `ioc_cron`, `ioc_binaries`, `ioc_users`, `ioc_ssh_keys`, `ioc_processes` and the raw collector result under `deep`. Runs one read-only script as root through a temporary Task Scheduler task (needs `deploy.stage_dir`, Step 2). `ioc_users` WARN lists accounts to confirm with the human; known ones go into `incident.allowed_users`.

## Step 7 (optional): monitoring

```bash
nas setup --json --webhook-file ~/.config/synology-nas-cli/webhook.json     # {"url": "https://...", "header": "Name: value"}
nas alert-deploy --json --test
```

Installs `nas alert --push` on the NAS as a root task every 10 minutes and points DSM's notification webhook at the same URL ([ALERTS.md](ALERTS.md)). Ask the human for the webhook URL and header (or a 1Password item holding them).

## What the human does, and when

| When | What |
|---|---|
| Step 1 | DSM address, account, password source, LAN range, staging folder |
| Step 2 exit 3 `otp` | the current 6-digit 2-step code (once; `--trust-device` keeps later logins code-free) |
| 1Password desktop integration | approve the `op` request in the 1Password app (first use) |
| Step 2 exit 5 | remove the AutoBlock entry from another device |
| Step 5 | read the plan; the firewall rescue steps (physical access) if a result says the login failed afterwards |
| Step 4/6 FAIL on `ransomware_files` / `ioc_*` | isolate the NAS (unplug the WAN side), per INCIDENT-C3RB3R.md |
| Tailscale | open the URL from `nas tailscale login-url` in a browser and approve the device |
