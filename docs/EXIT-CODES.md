# Exit codes

| Code | Meaning | Raised by |
|---|---|---|
| 0 | Success; for `alert` no warning/critical finding; for `incident` no FAIL item; for `incident fix` dry run, nothing to change, or every change applied and verified with no FAIL left | all commands |
| 1 | Command failed (DSM API error, HTTP failure after login, unreadable file), or the result needs attention: `alert` has a warning/critical finding, `incident` has a FAIL item, `incident fix` had a failed or refused change or a FAIL remains, `api` method that is not a read without `--allow-write` | all commands |
| 2 | Usage error (unknown option or argument) or invalid config file (`NAS_CONFIG` missing, bad JSON, unknown key, wrong type) | argument parser, config loader |
| 3 | Input required: a prompt or confirmation was needed but input is off (`--no-input`, `NAS_NO_INPUT=1`, or stdin is not a terminal). No credential source configured; `incident fix` without `--yes` | credentials, `incident fix`, `login` |
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
| `incident fix` | 0 dry run / nothing to do / all applied with no FAIL left, 1 a change failed or was refused (with nothing else to apply) or FAIL remains, 3 not confirmed and no input possible, 4-7 |
| `upgrade` | 0 including "already newest" and "PreCheck notes not confirmed" (`--json` field `action`), 1 failure |
| `login` / `logout` / `trust` / `config` | 0, 1, 2, 3-7 |
| `mcp` | 0 at end of input; tool failures are reported inside the protocol (`isError`, `_meta.exit_code` with the codes above) |
| every other command | 0, 1, 2, 3-7 |

`nas` never retries a failed sign-in: on 4 fix the credential source before running again (each failure counts toward AutoBlock: 10 within 5 minutes by DSM default). On 5 remove the address from Control Panel > Security > Protection > Allow/Block List from another address.
