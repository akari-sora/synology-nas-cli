"""Shared test setup: point NAS_CONFIG at a throwaway file before any nas module loads it."""
import atexit
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="nas-test-")
_OWNER = os.getpid()


def _cleanup():
    # only the process that made TMP removes it (forked/child processes inherit the atexit hook)
    if os.getpid() == _OWNER:
        shutil.rmtree(TMP, ignore_errors=True)


atexit.register(_cleanup)
for k in [k for k in os.environ if k.startswith("NAS_") or k == "OP_SERVICE_ACCOUNT_TOKEN"]:
    del os.environ[k]


def use_config(data: dict) -> str:
    path = os.path.join(TMP, "config.json")
    with open(path, "w") as f:
        json.dump(data, f)
    os.environ["NAS_CONFIG"] = path
    from nas import config
    config.load()
    return path


use_config({"session": {"cache_file": os.path.join(TMP, "session.json"),
                        "device_token_file": os.path.join(TMP, "device.json")},
            "credentials": {"op_token_file": os.path.join(TMP, "no-token-file")}})
