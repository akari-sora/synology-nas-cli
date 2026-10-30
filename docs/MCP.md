# `nas mcp`: MCP server

`nas mcp` speaks the Model Context Protocol over stdio: JSON-RPC 2.0, one JSON message per line on stdin, replies on stdout, diagnostics on stderr. Protocol versions: `2025-11-25` (default), `2025-06-18`, `2025-03-26`, `2024-11-05` (the client's requested version is used when listed). Capabilities: `tools` only. Methods: `initialize`, `ping`, `tools/list`, `tools/call`; notifications are accepted and ignored; a batch is answered with an error.

- One DSM session for the server's lifetime (`--backend`, `--lan-origin`, `--dsm-origin`, `--op-item`, `NAS_CONFIG` as for the CLI); it signs in again when DSM drops the session (106/107/119) and logs out at end of input. After a login, AutoBlock, unreachable or certificate error the next call opens a new session.
- Prompts answer with exit code 3 (as `--no-input`); the credential source is one that needs no typing (1Password service account, `password_command`, keychain entry from `nas login --save`, or a cached session from `nas login`). Step 1 for a new machine: the `setup` tool ([AGENT-RUNBOOK.md](AGENT-RUNBOOK.md)).
- `nas mcp --auto-confirm` (or `NAS_YES=1`, or config `assume_yes: true`): `incident_fix` applies without `confirm`.
- Result of `tools/call`: `content[0].text` is exactly the JSON `nas --json <command>` prints; `_meta.exit_code` is the CLI exit code ([EXIT-CODES.md](EXIT-CODES.md)); `isError: true` when the command failed (text = the error message). JSON Schemas for the main outputs: [`schemas/`](../schemas/).

## Tools

| Tool | Arguments | Same as | Writes |
|---|---|---|---|
| `setup` | `origin` (string or string array), `user`, `password_source` (`op:op://VAULT/ITEM/FIELD`, `command:CMD`, `keychain`, `env`), `otp_source` (`op`, `command:CMD`, `none`), `otp_code`, `trust_device` (bool), `tls` (`pin`/`verify`), `allowed_network` (string or string array), `stage_dir` (string), `webhook_file` (string) | `nas --json setup ...` | writes the config; one sign-in |
| `doctor` | - | `nas --json doctor` | no (one sign-in) |
| `whoami` | - | `nas --json whoami` | no |
| `status` | - | `nas --json status` | no |
| `health` | - | `nas --json health` | no |
| `net` | - | `nas --json net` | no |
| `services` | - | `nas --json services` | no |
| `logs` | `since` (string), `limit` (int), `top` (int) | `nas --json logs` | no |
| `alert` | `window` (int), `failed_threshold` (int) | `nas --json alert --no-update` | no |
| `incident_audit` | `probe` (bool), `scan` (bool), `deep` (bool), `hours` (int), `failed_threshold` (int) | `nas --json incident` | no (`scan` creates temporary File Station search tasks; `deep` a temporary root task and one result file, both deleted) |
| `incident_fix` | `confirm` (bool), `only` / `skip` (string or string array of fix names), `share` (string array), `ransom_scan`, `i_know_snapshots_may_rotate`, `upgrade`, `rotate_password`, `force_firewall`, `force_admin`, `force` (bool) | `nas --json incident fix --dry-run`; with `confirm: true` or `--auto-confirm`: `... --yes` | with `confirm: true` or `--auto-confirm` |
| `pkg_list` | - | `nas --json pkg list` | no |
| `volume_list` | - | `nas --json volume list` | no |
| `tailscale_status` | - | `nas --json tailscale status` | no |
| `api_read` | `api` (string, required), `method` (string, required), `params` (object), `version` (int) | `nas --json api API METHOD k=v ...` | no (writes: `nas api ... --allow-write` on the command line) |

Unknown arguments or wrong types are a JSON-RPC error `-32602`. `tools/list` returns each tool's `inputSchema` and `annotations` (`readOnlyHint`, `destructiveHint`).

## Client configuration

Replace `/path/to/synology-nas-cli` with the checkout (or use `nas` if installed with `pip`). `NAS_CONFIG` is optional when the config is at `~/.config/synology-nas-cli/config.json`.

Claude Code:

```bash
claude mcp add synology-nas --scope user -e NAS_CONFIG=$HOME/.config/synology-nas-cli/config.json -- /path/to/synology-nas-cli/bin/nas mcp
claude mcp add synology-nas --scope user -- /path/to/synology-nas-cli/bin/nas mcp --auto-confirm   # write tools apply directly
claude mcp list
```

Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, `%APPDATA%\Claude\claude_desktop_config.json` on Windows), and Cursor (`~/.cursor/mcp.json`, or `.cursor/mcp.json` in a project) use the same shape:

```json
{
  "mcpServers": {
    "synology-nas": {
      "command": "/path/to/synology-nas-cli/bin/nas",
      "args": ["mcp"],
      "env": {"NAS_CONFIG": "/Users/YOU/.config/synology-nas-cli/config.json"}
    }
  }
}
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.synology-nas]
command = "/path/to/synology-nas-cli/bin/nas"
args = ["mcp"]
env = { NAS_CONFIG = "/Users/YOU/.config/synology-nas-cli/config.json" }
```

Windows: `"command": "python"`, `"args": ["C:\\path\\to\\synology-nas-cli\\bin\\nas", "mcp"]`.

Check the server by hand:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | nas mcp
```
