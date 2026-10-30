# synology-nas-cli

`nas`: a CLI and stdio MCP server for a Synology NAS (DSM 7 Web API) and the C3RB3R / `.L0CK3D` incident. `AGENTS.md` is a symlink to this file.

## Layout

- `bin/nas`: launcher (adds the repo to `sys.path`, calls `nas.cli.main`). `pyproject.toml` installs the same as the `nas` console script.
- `nas/config.py`: JSON config (defaults <- `$NAS_CONFIG` or `~/.config/synology-nas-cli/config.json` <- env). `DEFAULTS` documents every key; `EXAMPLE` is what `nas config init` writes and must equal `config.example.json` (tested).
- `nas/credentials.py`: password chain (op -> command -> keychain -> env -> prompt), 2FA codes, keychain read/write, `op item edit` on stdin.
- `nas/backends.py`: transports. `password` (HTTPS through `make_opener`: no proxies, certificate verified or trusted on first use via `tls.known_certs_file`; session cache, `NAS_SID`, trusted-device token, renewal on 106/107/119), `chrome` (macOS AppleScript into a DSM tab), `local` (`synowebapi` as root on the NAS). `call_many(calls)` -> `[{ok, data | error, version}]`.
- `nas/commands.py`: read-only commands (`whoami`, `status`, `net`, `services`, `inventory`, `ransom-scan`, `exposure`, `health`, `logs`), raw `api`, shared helpers (`snapshot_state`, `public_addresses`, `probe_ports`, `fetch_connection_log`).
- `nas/incident.py`: `gather` (reads) -> `evaluate` (items) -> `plan` (changes, `FIX_ORDER`) -> `fix` (confirm, apply, verify, audit again). `UI` holds the DSM menu paths printed with each change.
- `nas/ioc.py`: C3RB3R indicators of compromise: connection-log scan (`exploit_attempts`), `COLLECTOR` (Python 3.8 script run as root by `--deep`; reads only, writes one O_EXCL|O_NOFOLLOW result file with a random marker), verdicts (`evaluate_deep`). Log text is data: `clean()` before display. `tests/ioc_check.py` runs the collector against a fake root tree.
- `nas/onboard.py`: `nas setup` (collects missing fields as `{missing: [{field, why, ask_user}]}` before writing anything; merges into the config file; one sign-in) and `nas doctor` (`{checks: [{name, status, detail, next_step}]}`). `tests/onboard_check.py` drives both against a fake DSM over HTTPS.
- `nas/mcp.py`: `nas mcp` (stdio MCP server; tools build CLI argv and call the same command functions). `nas/errors.py`: `NasError` subclasses with `exit_code` ([docs/EXIT-CODES.md](docs/EXIT-CODES.md)) and the `--no-input` switch (`can_prompt`).
- `schemas/`: JSON Schemas of `--json` outputs, checked by `tests/schema_check.py`; update them when an output changes.
- `nas/alert.py` (`alert`, `--push`), `nas/selfmon.py` (`alert-deploy`), `nas/upgrade.py`, `nas/manage.py` (`pkg`, `volume`, `tailscale`), `nas/advisories.py` (SA-26:13 / SA-26:14 tables).
- `docs/`: `AGENT-RUNBOOK.md`, `INCIDENT-C3RB3R.md`, `HARDENING.md`, `TROUBLESHOOTING.md`, `ALERTS.md`, `DSM-API-NOTES.md`, `MCP.md`, `EXIT-CODES.md`.
- `skills/`: agent skills (`synology-nas/SKILL.md`, `synology-ransomware-response/SKILL.md`) and installers (`install.sh`, `install.ps1`).
- `tests/`: offline checks (`*_check.py`, shared setup in `_env.py`, fake DSM in `fakenas.py`, `install_check.sh` for `skills/install.sh`), `run_offline.sh`, optional `smoke_live.sh`.

## Conventions

- Standard library only. Code runs on Python 3.8 (DSM's interpreter, used by `--backend local` and `alert-deploy`): keep `from __future__ import annotations`; no `str.removeprefix`, `dict | dict`, `functools.cache`, `zoneinfo`, `argparse.BooleanOptionalAction`, or runtime `list[str]`.
- Commands return `(lines, data)` or `(lines, data, exit_code)`; `--json` prints `data`.
- Expected failures raise `nas.errors.NasError` or a subclass (re-exported by `backends`); `cli.main` prints them as `nas: ...` and exits with the class's `exit_code`.
- Prompts go through `errors.can_prompt()`; nothing reads stdin when it is false (`nas mcp` uses stdin for the protocol). Confirmations accept `--yes` / `NAS_YES=1` / config `assume_yes` (`cli.assume_yes`). Checks that hold a change back name their override in the message (`--force-firewall`, `--force-admin`, `--i-know-snapshots-may-rotate`, `--force`).
- Global switches (`--json`, `--no-input`, `--yes`, `--force`) are accepted before or after the command (`cli.GLOBAL_FLAGS`).
- Site-specific values (addresses, share names, account names, webhook names, paths on the NAS) live in the config file; the code holds defaults only.
- Secrets (passwords, SIDs, SynoTokens, webhook headers) are never printed, logged or put on a command line. Commands with a secret go through stdin (`security -i`, `secret-tool store`, `op item edit`).
- DSM parameters are passed as Python values; `backends._encode_params` JSON-encodes them. Fields that need "a string containing JSON" are `json.dumps`ed once more by the caller.
- A failed DSM login is never retried with the same password (AutoBlock).
- Every DSM HTTP request goes through `PasswordBackend._open` (the proxy-free, pinned opener); other `urllib` calls (Synology download API, webhooks) use normal certificate verification.

## Adding an incident item or fix

1. Read what you need in `incident.gather` (read-only methods only; `commands.is_read_method` must accept them, `tests/incident_check.py` asserts the audit and `--dry-run` send nothing else).
2. Add the verdict in `incident.evaluate` (`item(id, PASS|WARN|FAIL|SKIP, detail, hint, fix_name)`); SKIP with the reason when the API is missing or unknown.
3. For a fix: build a `_change(...)` in `incident.plan` with the exact calls, an `apply` if it is more than sending those calls, and a `verify` that reads the state back. Add its name to `FIX_ORDER` and its DSM menu path to `UI`.
4. Extend `FakeNas` in `tests/incident_check.py`, then update the tables in `README.md`, `skills/synology-ransomware-response/SKILL.md`, `docs/HARDENING.md` and `docs/DSM-API-NOTES.md`.

## Tests

```bash
tests/run_offline.sh     # every offline check, with python3 and Python 3.8 (`uv python find 3.8`)
tests/smoke_live.sh      # read-only commands against the NAS in your config (optional)
```

## Technical facts worth knowing before touching DSM

- AutoBlock (DSM default): 10 failed sign-ins in 5 minutes block the source address, often permanently.
- The SynoToken is accepted only as a URL query parameter; DSM answers 119 otherwise.
- `SYNO.Core.TaskScheduler run` runs a task only with version 2.
- On models without immutable snapshots the API still accepts the WORM lock and scheduled snapshots then stop silently.
- Applying a default-deny firewall profile drops sessions from addresses it does not allow.
- More: [docs/DSM-API-NOTES.md](docs/DSM-API-NOTES.md) and [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).
