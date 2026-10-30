# synology-nas-cli

`nas`: a CLI for a Synology NAS (DSM 7 Web API) and the C3RB3R / `.L0CK3D` incident. `AGENTS.md` is a symlink to this file.

## Layout

- `bin/nas`: launcher (adds the repo to `sys.path`, calls `nas.cli.main`). `pyproject.toml` installs the same as the `nas` console script.
- `nas/config.py`: JSON config (defaults <- `$NAS_CONFIG` or `~/.config/synology-nas-cli/config.json` <- env). `DEFAULTS` documents every key; `EXAMPLE` is what `nas config init` writes and must equal `config.example.json` (tested).
- `nas/credentials.py`: password chain (op -> command -> keychain -> env -> prompt), 2FA codes, keychain read/write, `op item edit` on stdin.
- `nas/backends.py`: transports. `password` (HTTPS through `make_opener`: no proxies, certificate verified or trusted on first use via `tls.known_certs_file`; session cache, `NAS_SID`, trusted-device token, renewal on 106/107/119), `chrome` (macOS AppleScript into a DSM tab), `local` (`synowebapi` as root on the NAS). `call_many(calls)` -> `[{ok, data | error, version}]`.
- `nas/commands.py`: read-only commands, raw `api`, shared helpers (`snapshot_state`, `public_addresses`, `probe_ports`, `fetch_connection_log`).
- `nas/incident.py`: `gather` (reads) -> `evaluate` (items) -> `plan` (changes, `FIX_ORDER`) -> `fix` (confirm, apply, verify, audit again). `UI` holds the DSM menu paths printed with each change.
- `nas/alert.py` (`alert`, `--push`), `nas/selfmon.py` (`alert-deploy`), `nas/upgrade.py`, `nas/manage.py` (`pkg`, `volume`, `tailscale`), `nas/advisories.py` (SA-26:13 / SA-26:14 tables).
- `docs/`: `INCIDENT-C3RB3R.md`, `ALERTS.md`, `DSM-API-NOTES.md`. `skills/`: agent skills (`SKILL.md` with frontmatter).
- `tests/`: offline checks (`*_check.py`, shared setup in `_env.py`), `run_offline.sh`, optional `smoke_live.sh`.

## Conventions

- Standard library only. Code runs on Python 3.8 (DSM's interpreter, used by `--backend local` and `alert-deploy`): keep `from __future__ import annotations`; no `str.removeprefix`, `dict | dict`, `functools.cache`, `zoneinfo`, `argparse.BooleanOptionalAction`, or runtime `list[str]`.
- Commands return `(lines, data)` or `(lines, data, exit_code)`; `--json` prints `data`.
- Expected failures raise `nas.errors.NasError` (re-exported by `backends`); `cli.main` prints them as `nas: ...` and exits 1.
- Site-specific values (addresses, share names, account names, webhook names, paths on the NAS) live in the config file; the code holds defaults only.
- Secrets (passwords, SIDs, SynoTokens, webhook headers) are never printed, logged or put on a command line. Commands with a secret go through stdin (`security -i`, `secret-tool store`, `op item edit`).
- DSM parameters are passed as Python values; `backends._encode_params` JSON-encodes them. Fields that need "a string containing JSON" are `json.dumps`ed once more by the caller.
- A failed DSM login is never retried with the same password (AutoBlock).
- Every DSM HTTP request goes through `PasswordBackend._open` (the proxy-free, pinned opener); other `urllib` calls (Synology download API, webhooks) use normal certificate verification.

## Adding an incident item or fix

1. Read what you need in `incident.gather` (read-only methods only; `commands.is_read_method` must accept them, `tests/incident_check.py` asserts the audit and `--dry-run` send nothing else).
2. Add the verdict in `incident.evaluate` (`item(id, PASS|WARN|FAIL|SKIP, detail, hint, fix_name)`); SKIP with the reason when the API is missing or unknown.
3. For a fix: build a `_change(...)` in `incident.plan` with the exact calls, an `apply` if it is more than sending those calls, and a `verify` that reads the state back. Add its name to `FIX_ORDER` and its DSM menu path to `UI`.
4. Extend `FakeNas` in `tests/incident_check.py`, then update the tables in `README.md`, `skills/synology-ransomware-response/SKILL.md` and `docs/DSM-API-NOTES.md`.

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
- More: `docs/DSM-API-NOTES.md`.
