"""Site configuration: built-in defaults <- JSON file <- environment variables.

The file is $NAS_CONFIG, or ~/.config/synology-nas-cli/config.json. A missing
default file means "all defaults"; a missing $NAS_CONFIG file is an error.
Keys starting with "_" are comments and ignored. Unknown keys are an error,
so a typo does not silently fall back to a default.

Every module reads values through get(); nothing site-specific is fixed at
import time.
"""

from __future__ import annotations

import copy
import json
import os

DEFAULT_PATH = "~/.config/synology-nas-cli/config.json"

DEFAULTS = {
    # Label used in webhook bodies and as the DSM notification prefix ("[name]").
    "name": "nas",
    # Accept every confirmation (same as --yes / NAS_YES=1): incident fix, upgrade, api writes, MCP write tools.
    "assume_yes": False,
    # DSM origins for --backend password, tried in order (first one that accepts TCP wins).
    "origins": [],
    # Origins whose Chrome tab --backend chrome may use (default: "origins").
    "chrome_origins": [],
    "connect_timeout": 3.0,
    "tls": {
        # true: verify DSM's certificate against the system CAs (a real certificate for the origin's name).
        # false (default, DSM ships a self-signed one): trust on first use - the SHA-256 of the certificate
        # each origin presented first is stored in known_certs_file and any other certificate is refused
        # (`nas trust --reset ORIGIN` after replacing it).
        "verify": False,
        "known_certs_file": "~/.config/synology-nas-cli/known-certs.json",
    },
    # `exposure` / `incident --probe`: LAN address to probe (default: host of the first origin)
    # and public address when the NAS does not dial PPPoE itself (behind a router: the router's WAN IP).
    "lan_ip": "",
    "public_ip": "",
    # Sign-ins from these are expected. Empty = every non-global address (RFC 1918, 100.64.0.0/10,
    # loopback, link-local, IPv6 ULA). Also the firewall allow-list for `incident fix`.
    "allowed_networks": [],
    # Shares whose scheduled snapshots `alert` watches. `incident` checks every share when empty.
    "snapshot_shares": [],
    "snapshot_max_age_hours": 26,
    # Newest DSM build you expect for this model, e.g. "7.4.1-90080" (empty = skip the "behind" check).
    "latest_dsm": "",
    "credentials": {
        # Which source supplies the password: "auto" walks the chain in README order
        # (op, command, keychain, env, prompt); or force one of those names.
        "source": "auto",
        # 1Password references, e.g. "op://VAULT/ITEM/username" and "op://VAULT/ITEM/password".
        "op_username": "",
        "op_password": "",
        # On DSM error 403 (2FA), read the item's one-time password with `op item get --otp`.
        "op_otp": True,
        # Service-account token file, used when OP_SERVICE_ACCOUNT_TOKEN is unset and the file exists.
        "op_token_file": "~/.config/op/service-account-token",
        "username": "",
        # Any command that prints the password (run with /bin/sh -c).
        "password_command": "",
        # Any command that prints the current 6-digit 2FA code.
        "otp_command": "",
        # `nas login --save` stores the password here: "auto" (Keychain on macOS, secret-tool on
        # Linux), "keychain", "secret-tool", "op" (writes op_password), or "" (off).
        "store": "auto",
        # Service name for the Keychain / Secret Service entry.
        "store_service": "synology-nas-cli",
    },
    "session": {
        # `nas login` writes the DSM session here (mode 600) and later commands reuse it.
        "cache_file": "~/.cache/synology-nas-cli/session.json",
        # Trusted-device token from a 2FA login (`nas login --trust-device`), sent on later logins.
        "device_token_file": "~/.config/synology-nas-cli/device-token.json",
        "device_name": "synology-nas-cli",
        # Ask DSM for a trusted-device token on 2FA logins (also `nas login --trust-device`).
        "trust_device": False,
    },
    "alert": {
        "state_file": "~/.local/state/synology-nas-cli/baseline.json",
        # Report packages installed outside this volume, e.g. "/volume1" (empty = off).
        "package_volume": "",
        # Folders written continuously (e.g. camera recordings): <path>/<folder>/<sub-folder>/<files>.
        # Empty "folders" = check off.
        "recordings": {"path": "", "local_path": "", "folders": [], "max_age_min": 10, "note": ""},
    },
    "webhook": {
        # Where `alert-deploy` gets {"url", "header"} from (first one set wins):
        "op_item": "",            # "op://VAULT/ITEM": URL = the item's website, header = field below
        "op_header_field": "header",
        "file": "",               # JSON file {"url": "https://...", "header": "Name: value"}
        "command": "",            # command that prints that JSON
    },
    "deploy": {
        "root_dir": "/volume1/@nas-alert",
        # FileStation path in a shared folder the account can write, e.g. "/SHARE/.nas-cli-deploy".
        "stage_dir": "",
        "task_name": "nas-alert",
        "install_task_name": "nas-alert-install",
        "interval_min": 10,
        "dsm_webhook_name": "nas-alert",
        "dsm_webhook_prefix": "",  # default "[<name>]"
        "dsm_webhook_template": "Warning",
    },
    "upgrade": {"lang": "enu", "cache_dir": "~/.cache/synology-nas-cli/pat"},
    "incident": {
        # `incident fix`: retention for snapshot schedules it creates, and their time of day.
        "snapshot_retain_days": 14,
        "snapshot_hour": 3,
        "snapshot_minute": 30,
        # AutoBlock values `incident fix` sets.
        "autoblock_attempts": 10,
        "autoblock_within_mins": 5,
        # Also allow-list 127.0.0.1 in AutoBlock. Tailscale's DSM package in userspace mode (its default)
        # delivers every tailnet connection as 127.0.0.1, so one blocked tailnet device blocks all of them;
        # an SSH tunnel or local reverse proxy on the NAS looks the same.
        "autoblock_allow_loopback": False,
        # Indicators of compromise used by `exploit_attempts` and `--deep` besides the built-in injection strings
        # (PLUGIN_VALUE_END, LD_PRELOAD=, LD_DEBUG_OUTPUT): attacker addresses and extra strings to look for.
        "ioc_ips": ["46.8.78.122", "104.253.175.125"],
        "ioc_strings": [],
        # `--deep` ioc_users: local accounts (uid >= 1024) you know; admin and guest are always known.
        "allowed_users": [],
    },
}

# Written by `nas config init` (and kept identical to config.example.json by the tests).
EXAMPLE = {
    "_comment": "synology-nas-cli configuration. Every key is optional; see README.md#configuration. "
                "Addresses below are documentation examples (RFC 5737), replace them.",
    "name": "my-nas",
    "origins": ["https://192.0.2.10:5001", "https://my-nas.example-tailnet.ts.net:5001"],
    "lan_ip": "192.0.2.10",
    "public_ip": "",
    "allowed_networks": [],
    "snapshot_shares": ["photos", "documents"],
    "latest_dsm": "",
    "credentials": {
        "op_username": "op://VAULT/ITEM/username",
        "op_password": "op://VAULT/ITEM/password",
        "password_command": "",
        "otp_command": "",
    },
    "webhook": {"file": "~/.config/synology-nas-cli/webhook.json"},
    "deploy": {"stage_dir": "/SHARE/.nas-cli-deploy"},
}


class ConfigError(Exception):
    pass


_cfg = None
_path = None
_env_used: list = []


def _merge(base: dict, over: dict, where: str) -> dict:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if k.startswith("_"):
            continue
        if k not in base:
            raise ConfigError(f"{_path}: unknown key {where}{k!r}")
        b = base[k]
        if isinstance(b, dict):
            if not isinstance(v, dict):
                raise ConfigError(f"{_path}: {where}{k} must be an object")
            out[k] = _merge(b, v, f"{where}{k}.")
        elif isinstance(b, list):
            if not isinstance(v, list):
                raise ConfigError(f"{_path}: {where}{k} must be a list")
            out[k] = v
        elif isinstance(b, bool):
            if not isinstance(v, bool):
                raise ConfigError(f"{_path}: {where}{k} must be true or false")
            out[k] = v
        elif isinstance(b, (int, float)):
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise ConfigError(f"{_path}: {where}{k} must be a number")
            out[k] = v
        else:
            if not isinstance(v, str):
                raise ConfigError(f"{_path}: {where}{k} must be a string")
            out[k] = v
    return out


def _split(raw: str) -> list:
    return [o.strip().rstrip("/") for o in raw.split(",") if o.strip()]


def _apply_env(cfg: dict) -> None:
    env = os.environ
    used = []

    def take(name):
        v = env.get(name)
        if v:
            used.append(name)
        return v

    v = take("NAS_ORIGINS") or take("NAS_LAN_ORIGIN")  # NAS_LAN_ORIGIN: older name
    if v:
        cfg["origins"] = _split(v)
    v = take("NAS_CHROME_ORIGINS") or take("NAS_ORIGIN")  # NAS_ORIGIN: older name
    if v:
        cfg["chrome_origins"] = _split(v)
    v = take("NAS_OP_ITEM")
    if v:
        cfg["credentials"]["op_username"] = v.rstrip("/") + "/username"
        cfg["credentials"]["op_password"] = v.rstrip("/") + "/password"
    v = take("NAS_OP_TOKEN_FILE")
    if v:
        cfg["credentials"]["op_token_file"] = v
    v = take("NAS_USER")
    if v:
        cfg["credentials"]["username"] = v
    v = take("NAS_CREDENTIAL_SOURCE")
    if v:
        cfg["credentials"]["source"] = v
    v = take("NAS_OTP_COMMAND")
    if v:
        cfg["credentials"]["otp_command"] = v
    v = take("NAS_SESSION_FILE")
    if v:
        cfg["session"]["cache_file"] = v
    # NAS_PASSWORD_COMMAND, NAS_PASSWORD, NAS_SID, NAS_SYNOTOKEN and NAS_BACKEND are read
    # where they are used, so they never end up in `config show`.
    for name in ("NAS_PASSWORD_COMMAND", "NAS_PASSWORD", "NAS_SID", "NAS_SYNOTOKEN", "NAS_BACKEND"):
        if env.get(name):
            used.append(name)
    _env_used[:] = used


def config_path() -> tuple:
    """(path, explicit): explicit when it came from NAS_CONFIG."""
    p = os.environ.get("NAS_CONFIG")
    if p:
        return os.path.expanduser(p), True
    return os.path.expanduser(DEFAULT_PATH), False


def load(path: str | None = None) -> dict:
    """Load (or reload) the configuration. `path` overrides NAS_CONFIG."""
    global _cfg, _path
    if path:
        p, explicit = os.path.expanduser(path), True
    else:
        p, explicit = config_path()
    _path = p
    data = {}
    if os.path.exists(p):
        try:
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
        except ValueError as e:
            raise ConfigError(f"{p}: not valid JSON ({e})")
        if not isinstance(data, dict):
            raise ConfigError(f"{p}: the top level must be a JSON object")
        loaded = p
    elif explicit:
        raise ConfigError(f"NAS_CONFIG={p}: no such file (run `nas config init` to create one)")
    else:
        loaded = None
    cfg = _merge(DEFAULTS, data, "")
    _apply_env(cfg)
    cfg["origins"] = [o.rstrip("/") for o in cfg["origins"]]
    cfg["chrome_origins"] = [o.rstrip("/") for o in cfg["chrome_origins"]] or list(cfg["origins"])
    _cfg = cfg
    _path = loaded
    return cfg


def load_defaults() -> dict:
    """Built-in defaults plus environment, ignoring the file (for `nas doctor` / `nas setup` on a broken file)."""
    global _cfg, _path
    _path = None
    cfg = copy.deepcopy(DEFAULTS)
    _apply_env(cfg)
    cfg["chrome_origins"] = cfg["chrome_origins"] or list(cfg["origins"])
    _cfg = cfg
    return cfg


def get() -> dict:
    if _cfg is None:
        load()
    return _cfg


def loaded_from() -> str | None:
    get()
    return _path


def env_used() -> list:
    get()
    return list(_env_used)


def path(value: str) -> str:
    """Expand ~ in a configured path."""
    return os.path.expanduser(value) if value else value


def default_backend() -> str:
    return os.environ.get("NAS_BACKEND") or "password"


_SECRET_KEYS = {"password_command", "otp_command", "command"}


def masked(cfg: dict | None = None) -> dict:
    """Effective config with commands that may embed secrets replaced by '***'."""
    def walk(d):
        out = {}
        for k, v in d.items():
            if isinstance(v, dict):
                out[k] = walk(v)
            elif k in _SECRET_KEYS and v:
                out[k] = "***"
            else:
                out[k] = v
        return out
    return walk(cfg if cfg is not None else get())
