# Exit codes

| Code | Meaning | Raised by |
|---|---|---|
| 0 | Success; for `alert` no warning/critical finding; for `incident` no FAIL item; for `incident fix` dry run, nothing to change, or every change applied and verified with no FAIL left | all commands |
| 1 | Command failed (DSM API error, HTTP failure after login, unreadable file), or the result needs attention: `alert` has a warning/critical finding, `incident` has a FAIL item, `incident fix` had a failed change, a change waiting for an override flag, or a FAIL remains | all commands |
| 2 | Usage error (unknown option or argument) or invalid config file (`NAS_CONFIG` missing, bad JSON, unknown key, wrong type) | argument parser, config loader |
| 3 | Input needed: a value or confirmation that was not given and input is off (`--no-input`, `NAS_NO_INPUT=1`, or stdin is not a terminal). `setup` with missing fields (JSON `missing` list), no credential source, `incident fix`, `incident contain` (freeze) or `incident rescue` without `--yes`/`NAS_YES=1`, `incident rescue` without `--capture-dir` (or `--decrypt-from` without `--decrypt-to`), `api` write method without `--allow-write`/`--yes` | `setup`, credentials, `incident fix`, `incident contain`, `incident rescue`, `api`, `login` |
| 4 | DSM rejected the sign-in: 400 wrong account/password, 401 disabled, 402, 403 2-step code needed and none available, 404 2-step code wrong, 406 2-step enforced but not enrolled, 408/409/410 password expired | `password` backend login |
| 5 | DSM AutoBlock has blocked this address (login error 407) | `password` backend login |
| 6 | NAS unreachable (no origin accepted a TCP connection) or not ready (login error 498 upgrading, 499 post-upgrade tasks) | `password` backend |
| 7 | The DSM TLS certificate differs from the one trusted on first use (`nas trust --reset ORIGIN` after a deliberate change) | `password` backend |
| 130 | Interrupted (Ctrl-C) | all commands |

Per command:

| Command | Codes |
|---|---|
| `alert` | 0 clear, 1 warning/critical present or failure, 3-7 as above. With `--push`, a run skipped because another is still going exits 0. |
| `incident` | 0 no FAIL, 1 any FAIL or failure, 3-7 |
| `incident fix` | 0 dry run / nothing to do / all applied with no FAIL left, 1 a change failed, a change waits for an override flag (with nothing else to apply) or FAIL remains, 3 not confirmed and no input possible, 4-7 |
| `incident contain` | 0 scan with nothing to freeze; every listed process frozen (all threads `T`) and every `--stop-sync` package stopped; `--release` with every PID running again and every recorded package started. 1 a candidate exited, was skipped as a reused PID, or still has threads not stopped (`D` = waiting on I/O), a package did not stop/start, the root task failed, or not confirmed at the prompt. 3 candidates listed, not confirmed and no input possible (JSON has `candidates`). 4-7 |
| `incident rescue` | 0 every requested step done (or already done in `state.json`). 1 a step failed (`failed_step` names it, `steps.<name>.message` says why, `next_steps` what to do; the same command continues from there) or not confirmed at the prompt. 3 `--capture-dir` / `--decrypt-to` missing, or not confirmed and no input possible (JSON has `plan`). 4-7 |
| `setup` | 0 config written and one sign-in succeeded, 3 missing fields or a 2-step code needed (JSON `missing`), 4 sign-in rejected (reported once), 5, 6, 7 |
| `doctor` | 0 no check failed, 1 at least one check failed (JSON `checks[].next_step` says what to do) |
| `upgrade` | 0 including "already newest" and "PreCheck notes not confirmed" (`--json` field `action`), 1 failure |
| `login` / `logout` / `trust` / `config` | 0, 1, 2, 3-7 |
| `mcp` | 0 at end of input; tool failures are reported inside the protocol (`isError`, `_meta.exit_code` with the codes above) |
| every other command | 0, 1, 2, 3-7 |

`--yes`, `NAS_YES=1` and config `assume_yes` answer every CLI confirmation: `incident fix` applies (with `--upgrade`: install and reboot, PreCheck notes included), `upgrade` installs and reboots, `incident contain` freezes (and `--stop-sync` stops packages), `incident rescue` runs, `api` sends write methods. `nas mcp` does not read them: `incident_fix` applies with `confirm: true`, or without `confirm` on a server started with `--auto-confirm`.

On 4: correct the credential source, then run again (each failed sign-in counts toward AutoBlock: 10 within 5 minutes by DSM default; `nas` reports a failure once and stops). On 5: remove the address from Control Panel > Security > Protection > Allow/Block List from another address.
