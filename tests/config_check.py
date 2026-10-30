"""Offline checks of config loading, env overrides, validation, masking, `config init/show`."""
import contextlib
import io
import json
import os
import sys

import _env

from nas import cli, config

# defaults when the file is empty
_env.use_config({})
c = config.get()
assert c["origins"] == [] and c["credentials"]["source"] == "auto" and c["deploy"]["task_name"] == "nas-alert"
assert c["alert"]["recordings"]["folders"] == [] and c["incident"]["snapshot_retain_days"] == 14

# file values merge into nested sections; other defaults stay
_env.use_config({"name": "nas-test", "origins": ["https://192.0.2.10:5001/"], "deploy": {"stage_dir": "/files/x"},
                 "alert": {"recordings": {"folders": ["a"]}}, "_comment": "ignored"})
c = config.get()
assert c["name"] == "nas-test" and c["origins"] == ["https://192.0.2.10:5001"], c["origins"]
assert c["chrome_origins"] == ["https://192.0.2.10:5001"], "chrome origins default to origins"
assert c["deploy"]["stage_dir"] == "/files/x" and c["deploy"]["root_dir"] == "/volume1/@nas-alert"
assert c["alert"]["recordings"]["folders"] == ["a"] and c["alert"]["recordings"]["max_age_min"] == 10

# validation: unknown keys and wrong types are errors
for bad, why in [({"orgins": []}, "unknown key"), ({"deploy": {"stage": "x"}}, "unknown key deploy."),
                 ({"origins": "https://x"}, "must be a list"), ({"tls": {"verify": "yes"}}, "true or false"),
                 ({"connect_timeout": True}, "number"), ({"credentials": []}, "object")]:
    try:
        _env.use_config(bad)
    except config.ConfigError as e:
        assert why in str(e), (bad, str(e))
    else:
        raise AssertionError(f"{bad} accepted")

# an explicit NAS_CONFIG that does not exist is an error; the default path missing is not
os.environ["NAS_CONFIG"] = os.path.join(_env.TMP, "missing.json")
try:
    config.load()
    raise AssertionError("missing NAS_CONFIG accepted")
except config.ConfigError as e:
    assert "no such file" in str(e)

# environment overrides
_env.use_config({"origins": ["https://192.0.2.10:5001"]})
os.environ.update(NAS_ORIGINS="https://192.0.2.20:5001, https://192.0.2.21:5001", NAS_OP_ITEM="op://Vault/Item",
                  NAS_USER="ops", NAS_PASSWORD="pw-not-shown", NAS_CREDENTIAL_SOURCE="env")
config.load()
c = config.get()
assert c["origins"] == ["https://192.0.2.20:5001", "https://192.0.2.21:5001"], c["origins"]
assert c["credentials"]["op_password"] == "op://Vault/Item/password" and c["credentials"]["username"] == "ops"
assert c["credentials"]["source"] == "env"
assert "NAS_PASSWORD" in config.env_used() and "NAS_ORIGINS" in config.env_used()
for k in ("NAS_ORIGINS", "NAS_OP_ITEM", "NAS_USER", "NAS_PASSWORD", "NAS_CREDENTIAL_SOURCE"):
    del os.environ[k]
os.environ["NAS_LAN_ORIGIN"] = "https://192.0.2.30:5001"  # older name still honoured
config.load()
assert config.get()["origins"] == ["https://192.0.2.30:5001"]
del os.environ["NAS_LAN_ORIGIN"]

# masking: commands that may embed secrets are hidden
_env.use_config({"credentials": {"password_command": "echo hunter2", "otp_command": "oathtool x"},
                 "webhook": {"command": "cat secret.json"}})
m = config.masked()
assert m["credentials"]["password_command"] == "***" and m["credentials"]["otp_command"] == "***"
assert m["webhook"]["command"] == "***" and m["credentials"]["op_username"] == ""
out = io.StringIO()
with contextlib.redirect_stdout(out):
    rc = cli.main(["config", "show"])
assert rc == 0 and "hunter2" not in out.getvalue() and "cat secret.json" not in out.getvalue(), out.getvalue()
shown = json.loads(out.getvalue())
assert shown["_credential_source"]["source"] == "command" and shown["_file"].endswith("config.json")

# config init writes the example (mode 600) and refuses to overwrite
target = os.path.join(_env.TMP, "new", "config.json")
open(os.path.join(_env.TMP, "empty.json"), "w").write("{}")
os.environ["NAS_CONFIG"] = os.path.join(_env.TMP, "empty.json")
config.load()
os.environ["NAS_CONFIG"] = target
args = cli.parse_args(["config", "init"])
lines, data = cli.config_cmd(args)
assert data["path"] == target and oct(os.stat(target).st_mode & 0o777) == "0o600"
assert json.load(open(target)) == config.EXAMPLE
try:
    cli.config_cmd(args)
    raise AssertionError("overwrote without --force")
except Exception as e:
    assert "exists" in str(e)
config.load()  # the example itself must load cleanly
assert config.get()["name"] == "my-nas"

# the example file in the repo is the same as `config init` writes
with open(os.path.join(_env.ROOT, "config.example.json")) as f:
    assert json.load(f) == config.EXAMPLE, "config.example.json differs from config.EXAMPLE"
print(f"config checks ok (python {sys.version.split()[0]})")
